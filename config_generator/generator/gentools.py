import re
import logging
from config_generator.connections import connect, get_hostname
from config_generator.fstools import get_script_parameters
from config_generator.parameters import get_evpn_groups, get_ncs_ports_ranges

############################
# CONSTANTS
############################
SCRIPT_PARAMETERS = get_script_parameters()
EVPN_GROUPS = get_evpn_groups()
MIN_AGGR_PORT, MAX_AGGR_PORT = get_ncs_ports_ranges("min_aggr_port", "max_aggr_port")
MIN_INTERLINK_PORT, MAX_INTERLINK_PORT = get_ncs_ports_ranges("min_interlink_port",
                                                              "max_interlink_port")
MIN_UPLINK_PORT, MAX_UPLINK_PORT = get_ncs_ports_ranges("min_uplink_port",
                                                        "max_uplink_port")
############################
# CLASSES
############################


class AccessList:
    def __init__(self, name):
        self.name = name
        self.rules = []
        self.is_on_se = False
        self.is_on_pe = False

    def set_on_se(self):
        self.is_on_se = True

    def set_on_pe(self):
        self.is_on_pe = True

    def add_rules(self, rules):
        self.rules.append(rules)


class RemoteNeighbor:
    def __init__(self, ip, device_type):
        self.ip = ip
        self.pwid_list = []
        self.ssh = None
        self.old_loopback = None
        self.ncs_loopback = None
        self.ncs_loopback_backup = None
        self.hostname = None
        self.device_type = device_type
        self.ac_interfaces = []
        self._command_template = None

    def connect(self, username, password):
        self.ssh = connect(username, password, self.ip,
                           show_status=False,
                           device_type=self.device_type)
        self.hostname = get_hostname(self.ssh)

    def disconnect(self):
        self.ssh.disconnect()

    def add_pwid(self, pwid):
        self.pwid_list.append(pwid)

    def add_pwid_list(self, pwid_list):
        self.pwid_list.extend(pwid_list)

    def _get_ac_interface(self, pwid, *old_loopbacks):
        command = 'show xc all | i '
        for loopback in old_loopbacks:
            command += f'{loopback}:{pwid}'
            if old_loopbacks.index(loopback) != len(old_loopbacks) - 1:
                command += '|'
        output = self.ssh.send_command(command)
        if self.device_type == 'cisco_ios':
            search = re.search(r'((?:Gi|Te)(?:\d+\/?)*\.\d+)', output)
        elif self.device_type == 'cisco_xe':
            search = re.search(r'((?:Gi|Te)(?:\d+\/?)*:\d+)', output)
        if search:
            interface = search.group(1)
            logging.info(f'Remote {self.ip}: pwid {pwid} is on {interface}')
            return interface
        else:
            logging.info(f'Remote {self.ip}: pwid {pwid} hasn\'t been found')

    def get_ac_interfaces(self, *old_loopbacks, pwid_list=None):
        """Search for AC-interfaces for all pwids in pwid_list"""
        # Если pwid_list не передан, как атрибут, берем список из self.pwid_list
        if not pwid_list:
            if self.pwid_list:
                pwid_list = self.pwid_list
            else:
                logging.warning('pwid_list is empty. '
                                'No interface_list has been generated')
                raise ValueError
        for pwid in pwid_list:
            self.ac_interfaces.append(self._get_ac_interface(pwid, *old_loopbacks))
        logging.info('Interface_list is {}'.format(self.ac_interfaces))

    def _create_ios_config(self, se_loopback, se_loopback_backup, *old_loopbacks):
        """Create config for one interface"""
        self.get_ac_interfaces(*old_loopbacks)
        config = []
        for interface in self.ac_interfaces:
            config.append(f'no interface {interface}\ninterface {interface}')
            output = self.ssh.send_command(f'show running-config interface {interface}')
            for line in output.split('\n'):
                if re.search(r'(^\s)', line):
                    if re.search(r'^ xconnect', line):
                        pwid = re.search(r'xconnect \d+\.\d+\.\d+\.\d+ (\d+)', line).group(1)
                        config.append(re.sub(r'\d+\.\d+\.\d+\.\d+', se_loopback, line))
                        config.append(f'  backup peer {se_loopback_backup} {pwid}')
                    elif re.search(r'^  backup', line):
                        continue
                    else:
                        config.append(line)
            config.append('exit\n')
        return '\n'.join(config)

    def _create_xr_command_template(self, *old_loopbacks):
        command = 'show run formal l2vpn | i "'
        for loopback in old_loopbacks:
            command += f'neighbor.*{loopback} '
            command += 'pw-id {0}'
            if old_loopbacks.index(loopback) != len(old_loopbacks) - 1:
                command += '|'
        command += '"'
        return command

    def _create_xr_config(self, se_loopback, se_loopback_backup, *old_loopbacks):
        self._command_template = self._create_xr_command_template(*old_loopbacks)
        config = []
        for pwid in self.pwid_list:
            output = self.ssh.send_command(self._command_template.format(pwid))
            for line in output.split('\n'):
                if is_bd_config(line) and 'backup' not in line:
                    if 'split-horizon' not in line:
                        config.append('no ' + line)
                    config_line = re.sub(r'neighbor .*? ', f'neighbor {se_loopback} ',
                                         line, count=1)
                    config.append(config_line)
                    if 'split-horizon' not in line:
                        config.append(config_line + f'backup neighbor '
                                                    f'{se_loopback_backup} pw-id {pwid}')
                elif is_xc_config(line) and 'backup' not in line:
                    config.append('no ' + line)
                    config_line = re.sub(r'neighbor ipv4 .*? ',
                                         f'neighbor ipv4 {se_loopback} ', line, count=1)
                    config.append(config_line)
                    config.append(config_line + f'backup neighbor {se_loopback_backup} '
                                                f'pw-id {pwid}')
        return '\n'.join(config)

    def create_config(self, se_loopback, se_loopback_backup, *old_loopbacks):
        """Create config for all neighbor pwids"""
        config = '{}\n{}\n\n'.format(self.hostname, '*' * len(self.hostname))
        if self.device_type == 'cisco_ios':
            config += self._create_ios_config(se_loopback,
                                              se_loopback_backup,
                                              *old_loopbacks)
        elif self.device_type == 'cisco_xr':
            config += self._create_xr_config(se_loopback,
                                             se_loopback_backup,
                                             *old_loopbacks)
        # elif self.device_type == 'cisco_xe':
            # config += self._create_xr_config(se_loopback,
            #                                  se_loopback_backup,
            #                                  *old_loopbacks)

        # elif self.device_type == 'juniper_junos':
            # config += self._create_xr_config(se_loopback,
            #                                  se_loopback_backup,
            #                                  *old_loopbacks)
        config += '\n\n'
        return config


############################
# FUNCTIONS
############################

def is_shaping_policy(policy_name):
    return True if re.search(r'(\d+)(m|k)', policy_name) else False


def get_shaping_policies(vlans):
    policies = set()
    for vlan in vlans:
        policy_in = vlan.get('svi_policy_in')
        policy_out = vlan.get('svi_policy_out')
        if policy_in and is_shaping_policy(policy_in):
            policies.add(policy_in)
        if policy_out and is_shaping_policy(policy_out):
            policies.add(policy_out)

    return policies


def create_policy(name):
    policy_parameters = re.search(r'(\d+)(m|k)', name)
    if policy_parameters:
        shape_speed = round(int(policy_parameters.group(1)) * 1.1)
        prefix = policy_parameters.group(2)
        policy = f'policy-map {name}\n' \
                 f' class class-default\n' \
                 f'  shape average {shape_speed} {prefix}bps' \
                 f'\n !' \
                 f'\n  end-policy-map\n' \
                 f'!\n'
    else:
        return None
    return policy


def get_acl_list(connection):
    """

    :param connection:
    :return:
    """
    logger = logging.getLogger('get_acl_list')
    logger.info('Starting function')

    acl_names = set()
    acl_list = []
    acl_output = connection.send_command('sh run partition access-list')
    for line in acl_output.split(sep='\n'):

        # Стандартный и расширенный ACL:
        if line.startswith('ip access-list'):
            acl_name = re.search(r'ip access-list (?:standard|extended) (\S+)',
                                 line).group(1)
            if acl_names:  # Если это не первый ACL, сохраняем предыдущий
                acl_list.append(acl)
            acl = AccessList(acl_name)
            acl_names.add(acl_name)
        elif line.startswith(' permit') or line.startswith(' deny'):
            acl.add_rules(re.sub('^ ', '', line))

        # Нумерованный ACL:
        elif line.startswith('access-list'):
            num_acl_output = re.search(r'access-list (?P<name>\d+) (?P<rule>.*)', line)
            if num_acl_output:
                acl_name = num_acl_output.group('name')
                # Проверяем был ли расширенный ACL уже добавлен:
                if acl_name not in acl_names:
                    if acl_names:  # Если это не первый ACL, сохраняем предыдущий
                        acl_list.append(acl)
                    acl = AccessList(acl_name)
                    acl_names.add(acl_name)
                rule = num_acl_output.group('rule')
                acl.add_rules(rule)
        else:
            continue
    acl_list.append(acl)
    return acl_list


def is_vlan_fake(vlan):
    return True if vlan['fake'] else False


def get_acl_inuse(vlans):
    """Return unique set of ACL, which are used on BVIs"""
    acl_inuse = set()
    for vlan in vlans:
        if vlan.get('svi_acl_in'):
            acl_inuse.add(vlan.get('svi_acl_in'))
        if vlan.get('svi_acl_out'):
            acl_inuse.add(vlan.get('svi_acl_out'))
    return acl_inuse


def get_acl_location(vlans):
    """Return two sets, acl_on_pe and acl_on_se"""
    acl_on_pe = set()
    acl_on_se = set()
    for vlan in vlans:
        if vlan.get('svi_acl_in') and is_vlan_fake(vlan):
            acl_on_se.add(vlan.get('svi_acl_in'))
        elif vlan.get('svi_acl_in') and not is_vlan_fake(vlan):
            acl_on_pe.add(vlan.get('svi_acl_in'))
        if vlan.get('svi_acl_out') and is_vlan_fake(vlan):
            acl_on_se.add(vlan.get('svi_acl_out'))
        elif vlan.get('svi_acl_out') and not is_vlan_fake(vlan):
            acl_on_pe.add(vlan.get('svi_acl_out'))
    return acl_on_pe, acl_on_se


def get_unique_acl_list(acl_list, vlans):
    """

    :param vlans:
    :param acl_list:
    :return:
    """

    logger = logging.getLogger('get_unique_acl_list')
    logger.info('Starting function')

    acl_names = set()  # Множество всех имен ACL, проверка на повторы
    unique_acl_list = []  # Лист, содержащий уникальные используемые ACL
    acl_inuse = get_acl_inuse(vlans)
    acl_on_pe, acl_on_se = get_acl_location(vlans)

    for acl in acl_list:
        if acl.name in acl_inuse and acl.name not in acl_names:
            if acl.name in acl_on_se:
                acl.set_on_se()
            if acl.name in acl_on_pe:
                acl.set_on_pe()
            unique_acl_list.append(acl)
            acl_names.add(acl.name)
    return unique_acl_list


def get_neighbor_role(neighbor):
    return neighbor['role']


def split_neighbors_to_group(neighbor_list):
    """

    :param neighbor_list:
    :return:
    """

    logger = logging.getLogger('split_neighbors_to_group')
    logger.info('Starting function')

    aggregation_list = []  # Список соседей-агрегаций
    uplink_list = []  # Список соседей-аплинков
    interlink_list = []  # Список межкомплектов

    for neighbor in neighbor_list:
        if neighbor['alarm']:  # Обрабатываем только соседей без флага ALARM
            logger.info(f'Neighbor {neighbor["neighbor"]} has ALARM flag. Skipping')
            continue
        elif get_neighbor_role(neighbor) == 'aggregation':
            logger.info(f'Neighbor {neighbor["neighbor"]} is an aggregation')
            aggregation_list.append(neighbor)
        elif get_neighbor_role(neighbor) == 'uplink':
            logger.info(f'Neighbor {neighbor["neighbor"]} is an uplink')
            uplink_list.append(neighbor)
        elif get_neighbor_role(neighbor) == 'interlink':
            logger.info(f'Neighbor {neighbor["neighbor"]} is an interlink')
            interlink_list.append(neighbor)

    return aggregation_list, uplink_list, interlink_list


def sort_aggregations(aggregations):
    """Move MTU switches to first positions"""
    mtu1 = mtu2 = None
    for aggr in aggregations:
        if re.search(r'-MTU\d+-01', aggr['neighbor']):
            mtu1 = aggr
        elif re.search(r'-MTU\d+-02', aggr['neighbor']):
            mtu2 = aggr
    sorted_aggregations = []
    if mtu1:
        sorted_aggregations.append(mtu1)
    if mtu2:
        sorted_aggregations.append(mtu2)
    for aggr in aggregations:
        if aggr != mtu1 and aggr != mtu2:
            sorted_aggregations.append(aggr)

    return sorted_aggregations


def is_gist_vlan(vlan):
    return re.search(r'gist', vlan['vlan_name'].lower())


def set_evpn_groups_for_vlan(vlans):
    """

    :param vlans:
    :return:
    """

    logger = logging.getLogger('set_evpn_groups_for_vlan')
    logger.info('Starting function')

    for vlan in vlans:
        if vlan['is_l2/l3'] == 'L3':
            try:
                vlan['evpn_group'] = EVPN_GROUPS[vlan['svi_vrf']]
                logger.info(f"Vlan {vlan['vlan_id']} has marked as "
                            f"{vlan['evpn_group']} group")
            except KeyError:  # Если ключа нет, то это отдельный клиент
                vlan['evpn_group'] = 'EVPN_CLIENTS'
                logger.info(f"Vlan {vlan['vlan_id']} has marked as "
                            f"{vlan['evpn_group']} group")
        # L2 это EVPN_CLIENTS, либо EVPN_GIST:
        elif is_gist_vlan(vlan):
            vlan['evpn_group'] = 'EVPN_GIST'
            logger.info(f"Vlan {vlan['vlan_id']} has marked as "
                        f"{vlan['evpn_group']} group")
        else:
            vlan['evpn_group'] = 'EVPN_CLIENTS'
            logger.info(f"Vlan {vlan['vlan_id']} has marked as "
                        f"{vlan['evpn_group']} group")


def is_ucn_xc(xc):
    return re.search('UCN', str(xc['source_int_description']))


def is_szo_xc(xc):
    return re.search('SZO', str(xc['source_int_description']))


def is_gist_xc(xc):
    return re.search('gist', str(xc['source_int_description']).lower())


def is_pppoe_xc(xc):
    return re.search('pppoe', str(xc['source_int_description']).lower())


def add_is_pppoe_flags(xc_list):
    for xc in xc_list:
        if xc.get('source_int_description') and is_pppoe_xc(xc):
            xc['is_pppoe'] = True
        else:
            xc['is_pppoe'] = False


def set_evpn_groups_for_xc(xc_list):
    """

    :param xc_list:
    :return:
    """

    logger = logging.getLogger('set_evpn_groups_for_xc')
    logger.info('Starting function')

    for xc in xc_list:
        if xc.get('source_int_description') and is_ucn_xc(xc):
            xc['evpn_group'] = 'EVPN_UCN'
        elif xc.get('source_int_description') and is_szo_xc(xc):
            xc['evpn_group'] = 'EVPN_SZO'
        elif xc.get('source_int_description') and is_gist_xc(xc):
            xc['evpn_group'] = 'EVPN_GIST'
        elif xc.get('source_int_description') and is_pppoe_xc(xc):
            xc['evpn_group'] = 'EVPN_PPPoE'
        else:
            xc['evpn_group'] = 'EVPN_CLIENTS'

        logger.info(f"XC from {xc['source_port']} to {xc['remote_ip']} "
                    f"has marked as {xc['evpn_group']}")


def get_evi_id_for_vlan(vlan, ncs_evi_list):
    """

    :param ncs_evi_list:
    :param vlan:
    :return:
    """

    logger = logging.getLogger('get_evi_id_for_vlan')
    logger.info('Starting function')

    if vlan['vlan_id'] not in ncs_evi_list:
        evi_id = vlan['vlan_id']
        ncs_evi_list.append(evi_id)
    # В случае дублирования добавляем слева к номеру EVI ID 5, 6 и т.д:
    else:
        vlan['is_duplicated'] = True
        for evi_id_addiction in range(5, 30):
            if len(vlan['vlan_id']) == 1:
                evi_id = str(evi_id_addiction) + '00' + vlan['vlan_id']
            elif len(vlan['vlan_id']) == 2:
                evi_id = str(evi_id_addiction) + '0' + vlan['vlan_id']
            else:
                evi_id = str(evi_id_addiction) + vlan['vlan_id']
            if evi_id not in ncs_evi_list:
                ncs_evi_list.append(evi_id)
                break

    return evi_id


def get_evi_id_for_xc(xc, ncs_evi_list):
    """

    :param ncs_evi_list:
    :param xc:
    :return:
    """

    logger = logging.getLogger('get_evi_id_for_xc')
    logger.info('Starting function')

    if xc['dot1q'] not in ncs_evi_list:
        evi_id = xc['dot1q']
        ncs_evi_list.append(evi_id)
    else:
        # PPPoE XC и XC между PE могут повторяться, это не дубликаты
        if xc['evpn_group'] != 'EVPN_PPPoE' and not xc.get('not_xc'):
            xc['is_duplicated'] = True
            for evi_id_addiction in range(5, 30):
                if len(xc['dot1q']) == 1:
                    evi_id = str(evi_id_addiction) + '00' + xc['dot1q']
                elif len(xc['dot1q']) == 2:
                    evi_id = str(evi_id_addiction) + '0' + xc['dot1q']
                else:
                    evi_id = str(evi_id_addiction) + xc['dot1q']
                if evi_id not in ncs_evi_list and xc['evpn_group'] != 'EVPN_PPPoE':
                    ncs_evi_list.append(evi_id)
                    break
        else:
            evi_id = xc['dot1q']

    return evi_id


def get_pppoe_xc_diff(xc_list, hostname):
    """

    :param hostname:
    :param xc_list:
    :return: pppoe_xc_diff_list
    """

    logger = logging.getLogger('get_pppoe_xc_diff')
    logger.info('{} Starting function'.format(hostname))

    pe1_pppoe_xc = []  # Список XC (dot1q) с текущей PE
    pe2_pppoe_xc = []  # Список XC (dot1q) с другой PE
    pppoe_xc_diff = []  # Список XC (dot1q), отсутствующих на текущей PE

    for xc in xc_list:
        if xc['evpn_group'] == 'EVPN_PPPoE':
            if xc['hostname'] == hostname:
                pe1_pppoe_xc.append(xc['dot1q'])
            else:
                pe2_pppoe_xc.append(xc['dot1q'])
    for pppoe_xc in pe2_pppoe_xc:
        if pppoe_xc not in pe1_pppoe_xc:
            pppoe_xc_diff.append(pppoe_xc)
    logger.info(f"{hostname} PPPoE XC diff list: {pppoe_xc_diff}")

    return pppoe_xc_diff


def get_pppoe_neighbors(xc_list, hostname1, hostname2):
    """

    :param xc_list:
    :param hostname1:
    :param hostname2:
    :return:
    """

    logger = logging.getLogger('get_pppoe_neighbors')
    logger.info('Starting function')

    neighbors = {}  # Словарь, содержащий значения pe_hostname:remote_pe_ip
    for xc in xc_list:
        if xc['evpn_group'] == 'EVPN_PPPoE' and xc['hostname'] == hostname1:
            neighbors[hostname1] = xc['remote_ip']
        elif xc['evpn_group'] == 'EVPN_PPPoE' and xc['hostname'] == hostname2:
            neighbors[hostname2] = xc['remote_ip']
    logger.info(f'PPPoE neighbors dictionary contains: {neighbors}')

    return neighbors


def get_old_neighbor_lo30(connection):
    return connection['old_neighbor_lo30']


def need_convertation_to_vlan(xc_list, hostname, old_neighbor_lo30):
    logger = logging.getLogger('need_convertation_to_vlan')
    logger.info(f'{hostname} Starting function')
    for xc in xc_list:
        if xc['hostname'] == hostname and xc['remote_ip'] == old_neighbor_lo30:
            xc['not_xc'] = True


def convert_xc_to_vlan(xc_list, vlans, hostname):
    logger = logging.getLogger('convert_xc_to_vlan')
    logger.info('Starting function')

    pwid_list = []
    xc_to_convert = []
    converted_xc = []

    for xc in xc_list:
        if xc.get('not_xc'):
            if xc['hostname'] == hostname:
                pwid_list.append(xc['pwid'])
                xc_to_convert.append(xc)
            elif xc['pwid'] in pwid_list:
                for second_xc in xc_to_convert:
                    if xc['pwid'] == second_xc['pwid']:
                        vlans.append({'vlan_id': xc['dot1q'],
                                      'is_l2/l3': 'L2',
                                      'is_merged': True,
                                      'neighbors': xc['source_neighbor'] + ', ' +
                                                   second_xc['source_neighbor'],
                                      'vlan_name': xc['source_int_description'],
                                      'alarm_neighbors': None,
                                      'alarm_hsrp': None,
                                      'alarm_subnets': None,
                                      'alarm_intersection': None,
                                      'is_in_eigrp': None
                                      })
                        converted_xc.append(xc)
                        converted_xc.append(second_xc)
                        break

    for xc in converted_xc:
        xc_list.remove(xc)


def get_fake_scheme(vlan_list):
    """

    :param vlan_list:
    :return:
    """

    logger = logging.getLogger('get_fake_scheme')

    for vlan in vlan_list:
        logger.info(f"Starting func for vlan {vlan['vlan_id']}")
        # Проверка MGMT вланов:
        if vlan.get('svi_vrf') == 'MGMT' \
                and vlan.get('vlan_id') not in ('1', '2', '888', '901'):
            vlan['fake'] = 2
            logger.info(f"Vlan {vlan['vlan_id']} is FAKE2 (MGMT)")
        # Проверка банков:
        elif vlan.get('svi_vrf') and 'bank' in vlan['svi_vrf'].lower():
            vlan['fake'] = 1
            logger.info(f"Vlan {vlan['vlan_id']} is FAKE1 ('BANK' IN VRF)")
        elif vlan.get('svi_descr') and 'bank' in vlan['svi_descr'].lower():
            vlan['fake'] = 1
            logger.info(f"Vlan {vlan['vlan_id']} is FAKE1 ('BANK' IN DESCR)")
        # Проверка остальных исключений:
        elif vlan.get('svi_vrf') in ['TATTRANSGAZ', 'kes', 'n_Zelax', 'MONITOR_TLS']:
            vlan['fake'] = 1
            logger.info(f"Vlan {vlan['vlan_id']} is FAKE1 "
                        f"(VRF {vlan['svi_vrf']} is an exception)")
        elif vlan.get('vlan_id') in ['3004']:
            vlan['fake'] = 1
            logger.info(f"Vlan {vlan['vlan_id']} is FAKE1 (Vlan is an exception)")
        else:
            vlan['fake'] = 0
            logger.info(f"Vlan {vlan['vlan_id']} is not fake")


def format_acl_rule(rule):
    return rule.replace(' ip ', ' ipv4 ')


def create_acl_config(acl):
    logger = logging.getLogger('create_acl_config')
    logger.info('Starting function')

    config = ''
    rule_index = 10
    for rule in acl.rules:
        config += f"ipv4 access-list {acl.name} {rule_index} {format_acl_rule(rule)}\n"
        rule_index += 10

    return config


def format_acl_name_for_se(acl_name, hostname):
    logger = logging.getLogger('change_acl_name_for_se')
    logger.info('Starting function')

    return re.search(r'(\S+)+PE\d', hostname).group(1) + acl_name


def create_remotes_config(**kwargs):

    logger = logging.getLogger('create_remotes_config')
    logger.info('Starting function')

    # Промежуточный словарь ip:[pwid_list]
    d = {}
    for xc in kwargs["xconnects"]:
        d.setdefault(xc['remote_lo2'], []).append(xc['pwid'])

    # Собираем список всех удаленных соседей (объектов RemoteNeighbor):

    remote_neighbors = []
    for remote_ip in d.keys():
        neighbor = RemoteNeighbor(remote_ip, kwargs['device_type'])
        neighbor.add_pwid_list(d[remote_ip])
        remote_neighbors.append(neighbor)

    # Проходим по всем соседям и генерируем конфиг
    config = ''
    for neighbor in remote_neighbors:
        neighbor.connect(kwargs["ssh_username"], kwargs["ssh_password"])
        config += neighbor.create_config(kwargs["se_loopback"],
                                         kwargs["se_loopback_backup"],
                                         kwargs["pe1_old_lo30"],
                                         kwargs["pe2_old_lo30"])
        neighbor.disconnect()

    return config


def format_data_from_table(sheet_title, data):
    if sheet_title == 'Общий список VLAN':
        return format_vlan_list(data)
    elif sheet_title == 'Общий список соседей':
        return format_neighbor_list(data)
    elif sheet_title == 'Список XC':
        return format_xc_list(data)
    else:
        return data


def format_vlan_list(vlan_list):
    logger = logging.getLogger('format_vlan_list')
    logger.info('Start function')

    formatted_vlan_list = []
    for vlan in vlan_list:
        if not vlan['alarm_neighbors'] and not vlan['alarm_hsrp'] \
                and not vlan['alarm_subnets'] \
                and not vlan['alarm_intersection'] \
                and not vlan['is_in_eigrp']:
            if vlan.get('svi_ip_secondary'):
                vlan['svi_ip_secondary'] = vlan['svi_ip_secondary'].split(', ')
            formatted_vlan_list.append(vlan)
        else:
            logger.info(f'Vlan {vlan["vlan_id"]} has ALARM flag. Skipping')
    return formatted_vlan_list


def format_neighbor_list(neighbor_list):
    for neighbor in neighbor_list:
        if re.search(r'(^|\s)gist', neighbor['neighbor'].lower()):
            neighbor['is_gist_router'] = True
            neighbor['neighbor'] = 'GIST_ROUTER'
    return neighbor_list


def format_xc_list(xc_list):
    logger = logging.getLogger('format_xc_list')
    logger.info('Start function')
    formatted_xc_list = []
    for xc in xc_list:
        if not xc.get('alarm'):
            formatted_xc_list.append(xc)
        else:
            logger.info(f'{xc["hostname"]} XC from {xc["source_port"]} '
                        f'to {xc["remote_ip"]} has ALARM flag. Skipping')
    return formatted_xc_list


def get_esi_template(loopback30):
    logger = logging.getLogger('get_esi_template')
    logger.info(f'Creating Ethernet Segment ID for {loopback30}')

    lo30_octets = []
    esi_template = ''
    for group in range(1, 5):
        lo30_octet = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', loopback30).group(group)
        if len(lo30_octet) == 1:
            lo30_octet = '0' + lo30_octet
        elif len(lo30_octet) == 3:
            lo30_octets.append(lo30_octet[0:2])
            lo30_octets.append(lo30_octet[2] + '0')
            continue
        lo30_octets.append(lo30_octet)

    for esi_octet in range(0, 8):
        try:
            esi_template += lo30_octets[esi_octet] + '.'
        except IndexError:
            esi_template += '00.'

    esi_template += '{}'
    logger.info(f'Ethernet Segment ID template is: {esi_template}')

    return esi_template


def get_7600s_lo30(connection):
    output = connection.send_command('sh run int lo30 | i ip address')
    return re.search(r'ip address (\d+.\d+.\d+.\d+)', output).group(1)


def create_ncs_hostname(old_hostname):
    hostname = re.search(r'(\S+)+PE\d', old_hostname).group(1) + 'NCS-' + \
               re.search(r'(PE.*)', old_hostname).group(1)
    return hostname


def get_bgp_vpnv4_neighbors(connection):
    output = connection.send_command('show run partition router bgp 65000 | '
                                     'sec address-family vpnv4')
    return re.findall(r'neighbor (\S+) activate', output)


def is_bd_config(line):
    return True if line.startswith('l2vpn bridge') else False


def is_xc_config(line):
    return True if line.startswith('l2vpn xconnect') else False


def write_init_config(hostname, loopback2, loopback30, ncs_config_file):
    init_config = [
        "service unsupported-transceiver\n",
        f"hostname {hostname}\n",
        "group auto-bw\n",
        " interface 'tunnel-te.*'\n",
        " interface 'tunnel-te.*'  ipv4 unnumbered Loopback30\n",
        " interface 'tunnel-te.*'  load-interval 30\n",
        " interface 'tunnel-te.*'  auto-bw \n",
        " interface 'tunnel-te.*'  auto-bw  bw-limit min 50000 max 300000000\n",
        " interface 'tunnel-te.*'  auto-bw  overflow threshold 10 min 5000 "
        "limit 3\n",
        " interface 'tunnel-te.*'  auto-bw  adjustment-threshold 10 min 10000\n",
        " interface 'tunnel-te.*'  auto-bw  underflow threshold 10 "
        "min 5000 limit 3\n",
        " interface 'tunnel-te.*'  auto-bw  application 600\n",
        " interface 'tunnel-te.*'  logger events lsp-status state\n",
        " interface 'tunnel-te.*'  logger events pcalc-failure\n",
        " interface 'tunnel-te.*'  logger events lsp-status "
        "insufficient-bandwidth\n",
        " interface 'tunnel-te.*'  path-option 10 dynamic\n",
        " interface 'tunnel-te.*'  logger events link-status\n",
        "end-group\n",
        "clock timezone MSK Europe/Moscow\n",
        # LOGGING:
        "logger events threshold 90\n",
        "logger events buffer-size 1000000\n",
        "logger events level notifications\n",
        "logger buffered 10000000\n",
        "logger buffered notifications\n",
        "logger 172.16.31.31 vrf MGMT severity info port default\n",
        "logger suppress rule license alarm LICENSE SMART_LIC "
        "EVAL_EXPIRED_WARNING\n",
        "logger suppress apply rule license\n",
        "logger suppress apply rule license all-of-router\n",
        "logger suppress rule tr69block alarm L2 L2RIB DUP_HOST\n",
        "logger suppress apply rule tr69block\n",
        "logger suppress apply rule tr69block all-of-router\n",
        "logger suppress rule ldpduplicate alarm ROUTING LDP PEER_DUP_ADDRS\n",
        "logger suppress apply rule ldpduplicate\n",
        "logger suppress apply rule ldpduplicate all-of-router\n",
        f"logger hostnameprefix {hostname}\n",
        # ACCESS:
        "telnet vrf MGMT ipv4 server max-servers 20 access-list VTY_ACCESS\n",
        "telnet vrf default ipv4 server max-servers 10\n",
        "tacacs source-interface Loopback2 vrf MGMT\n",
        "aaa accounting exec default start-stop group TAT\n",
        "aaa accounting network default start-stop group TAT\n",
        "aaa accounting commands default start-stop group TAT\n",
        "aaa group server tacacs+ TAT\n",
        "aaa group server tacacs+ TAT vrf MGMT\n",
        "aaa group server tacacs+ TAT server-private 172.16.31.251 port 4949\n",
        "aaa group server tacacs+ TAT server-private 172.16.31.251 port 4949 "
        "key 7 075B781817\n",
        "aaa authentication login default local group TAT\n",
        "line default exec-timeout 0 0\n",
        "line default session-limit 20\n",
        "vty-pool default 0 15\n",
        # CDP:
        "cdp\n",
        # LACP:
        "lacp system mac 0001.0001.0001\n",
        # SNMP:
        "snmp-server ifindex persist\n",
        "snmp-server vrf MGMT\n",
        "snmp-server host 10.100.1.10 traps version 2c ttmon4vz4zd322\n",
        "snmp-server host 172.16.31.41 traps version 2c ttmon4vz4zd322\n",
        "snmp-server user Billing-V3-Snmp IRBIS-GROUP v3 auth md5 encrypted "
        "105D2D1F4846015F41002C7D027164787A4A201C5152 priv aes 128 encrypted "
        "03160C535F2832486A44110F105F0F040E67200C1F6321\n",
        "snmp-server view IRBIS-VIEW system included\n",
        "snmp-server view IRBIS-VIEW interfaces included\n",
        "snmp-server community ttmon4vz4zd322 RW IPv4 SNMP_MON\n",
        "snmp-server group IRBIS-GROUP v3 priv write IRBIS-VIEW IPv4 SNMP_MON\n",
        "snmp-server User Billing-V3-Snmp IRBIS-GROUP v3 auth md5 "
        "sDf-1s4-df6F97-89Gj23 priv aes 128 r789GsdD-hjg-dhj-kHW0t IPv4 11\n",
        "snmp-server traps snmp linkup\n",
        "snmp-server traps snmp linkdown\n",
        "snmp-server contact NULL\n",
        "snmp-server trap-source Loopback2\n",
        # DHCP:
        "dhcp ipv4 vrf WAP relay profile RELAY\n",
        "dhcp ipv4 vrf WUS relay profile RELAY\n",
        "dhcp ipv4 vrf FTTH relay profile RELAY_FTTH\n",
        "dhcp ipv4 vrf IPTV relay profile RELAY\n",
        "dhcp ipv4 vrf TR69 relay profile RELAY\n",
        "dhcp ipv4 vrf SIP_ADSL relay profile RELAY\n",
        "dhcp ipv4 profile RELAY relay\n",
        "dhcp ipv4 profile RELAY relay helper-address vrf MGMT 10.16.252.20 "
        f"giaddr {loopback2}\n",
        "dhcp ipv4 profile RELAY relay helper-address vrf MGMT 10.16.252.21 "
        f"giaddr {loopback2}\n",
        "dhcp ipv4 profile RELAY relay relay information option vpn\n",
        "dhcp ipv4 profile RELAY relay relay information option\n",
        "dhcp ipv4 profile RELAY relay relay information policy encapsulate\n",
        "dhcp ipv4 profile RELAY relay relay information option vpn-mode cisco\n",
        "dhcp ipv4 profile RELAY relay relay information option allow-untrusted\n",
        "dhcp ipv4 profile trust snoop\n",
        "dhcp ipv4 profile trust snoop trusted\n",
        "dhcp ipv4 profile untrust snoop\n",
        "dhcp ipv4 profile untrust snoop relay information option "
        "allow-untrusted\n",
        # NTP:
        "ntp server vrf MGMT 10.1.1.1 version 3 source Loopback2\n",
        # CALL-HOME:
        "call-home service active\n",
        "call-home contact smart-licensing\n",
        "call-home profile CiscoTAC-1\n",
        "call-home profile CiscoTAC-1 active\n",
        "call-home profile CiscoTAC-1 destination transport-method http\n",
        # HW-MODULE:
        "hw-module profile acl egress layer3 interface-based\n",
        "hw-module profile qos hqos-enable\n",
        "hw-module profile bundle-scale 1024\n",
        "hw-module vrrpscale enable\n",
        "!\n",
        "hw-module quad 0 location 0/0/CPU0 mode 10g\n",
        "hw-module quad 1 location 0/0/CPU0 mode 10g\n",
        # INTERFACES:
        "interface Loopback2\n",
        "interface Loopback2 vrf MGMT\n",
        f"interface Loopback2 ipv4 address {loopback2} "
        "255.255.255.255\n"
        "interface Loopback30\n",
        f"interface Loopback30 ipv4 address {loopback30} "
        "255.255.255.255\n",
        "interface MgmtEth0/RP0/CPU0/0 shutdown\n",
        "interface HundredGigE0/0/1/0 shutdown\n",
        "interface HundredGigE0/0/1/1 shutdown\n",
        "!\n",
        # PREFIX-SETS:
        "prefix-set FTTH_STB_NET\n",
        "  10.232.0.0/14 le 24,\n",
        "  10.236.0.0/14 le 24,\n",
        "  10.244.0.0/14 le 24,\n",
        "  10.216.0.0/13 le 24,\n",
        "  10.200.0.0/13 le 27,\n",
        "  10.240.0.0/14 le 27,\n",
        "  10.192.0.0/13 le 27\n",
        "end-set\n",
        "!\n",
        "prefix-set stream\n",
        "  10.20.5.152/30\n",
        "end-set\n",
        "!\n",
        # ROUTE-POLICIES:
        "route-policy FTTH_STB_TO_IPTV\n"
        "   if destination in FTTH_STB_NET then\n"
        "     set extcommunity rt(65000: 90) additive"
        "endif\n"
        "end-policy\n"
        "!\n"
        "route-policy stream\n",
        "  if destination in stream then\n",
        "    drop\n",
        "  else\n",
        "    pass\n",
        "  endif\n",
        "end-policy\n",
        "!\n",
        # ROUTER OSPF:
        f"router ospf 1 router-id {loopback30}\n",
        "router ospf 1 bfd minimum-interval 100\n",
        "router ospf 1 bfd fast-detect\n",
        "router ospf 1 bfd multiplier 3\n",
        "router ospf 1 mpls ldp sync\n",
        "router ospf 1 mpls ldp auto-config\n",
        "router ospf 1 timers throttle lsa all 30 100 1000\n",
        "router ospf 1 timers throttle spf 30 100 1000\n",
        "router ospf 1 auto-cost reference-bandwidth 80000\n",
        "router ospf 1 redistribute connected\n",
        "router ospf 1 area 0\n",
        "router ospf 1 area 0 mpls traffic-eng\n",
        "router ospf 1 area 0 interface Loopback30\n",
        "router ospf 1 area 0 interface Loopback30 passive enable\n"
        # ROUTER BGP:
        "router bgp 65000\n",
        "router bgp 65000 timers bgp 1 20\n",
        f"router bgp 65000 bgp router-id {loopback30}\n",
        "router bgp 65000 bgp update-delay 1\n",
        "router bgp 65000 bgp log neighbor changes detail\n",
        "router bgp 65000 address-family vpnv4 unicast\n",
        "router bgp 65000 address-family l2vpn evpn\n",
        "router bgp 65000 neighbor-group iBGP\n",
        "router bgp 65000 neighbor-group iBGP remote-as 65000\n",
        "router bgp 65000 neighbor-group iBGP update-source Loopback30\n",
        # EVPN:
        "evpn\n",
        "evpn bgp\n",
        # L2VPN:
        "l2vpn\n",
        "l2vpn load-balancing flow src-dst-mac\n",
        # MPLS:
        "mpls traffic-eng\n",
        "mpls ldp\n",
        "mpls ldp log hello-adjacency\n",
        "mpls ldp log neighbor\n",
        "mpls ldp log session-protection\n",
        "mpls ldp discovery hello interval 1\n",
        f"mpls ldp router-id {loopback30}\n",
        "mpls ldp session protection\n",
        "mpls ldp address-family ipv4\n",
        # MULTICAST:
        "multicast-routing address-family ipv4\n",
        "multicast-routing address-family ipv4 rate-per-route\n",
        "multicast-routing address-family ipv4 interface all enable\n",
        "multicast-routing address-family ipv4 accounting per-prefix\n",
        "multicast-routing\n",
        # IGMP:
        "router igmp version 2\n",
        # PIM:
        "router pim\n",
        "router pim address-family ipv4 rp-address 10.30.0.14 AUTORP_NETWORKS\n",
        "router pim address-family ipv4 old-register-checksum\n",
        "router pim address-family ipv4 log neighbor changes\n",
        # IGMP:
        "igmp snooping profile multicast\n",
        "igmp snooping profile multicast router-alert-check disable\n",
        "igmp snooping profile multicast-guard\n",
        "igmp snooping profile multicast-guard router-guard\n",
        "igmp snooping profile multicast-mrouter\n",
        "igmp snooping profile multicast-mrouter mrouter\n",
        # CLASS-MAP, POLICY-MAP:
        "class-map match-any BULK\n",
        " match dscp ipv4 af11\n",
        " match mpls experimental topmost 1\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any IPTV\n",
        " description -=Match_Streaming_Video_Traffic=-\n",
        " match dscp ipv4 cs4\n",
        " match mpls experimental topmost 4\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any MGMT\n",
        " description -=Match_Routing_and_Management_Traffic=-\n",
        " match dscp ipv4 cs6 cs2\n",
        " match mpls experimental topmost 6\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any VOICE\n",
        " description -=Match_VOICE_and_Videoconference_Traffic=-\n",
        " match mpls experimental topmost 5\n",
        " match dscp ipv4 ef cs5\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any BULK-TC\n",
        " description 'Match BULK priority traffic-class 4'\n",
        " match traffic-class 4\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any IPTV-TC\n",
        " description 'Match video traffic-class 6'\n",
        " match traffic-class 6\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any MGMT-TC\n",
        " description 'Match highest priority traffic-class 1'\n",
        " match traffic-class 1\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any BUSINESS\n",
        " description -=Match_Business_Critical_Traffic=-\n",
        " match dscp ipv4 af31 cs3\n",
        " match mpls experimental topmost 3\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any VOICE-TC\n",
        " description 'Match high priority traffic-class 7'\n",
        " match traffic-class 7\n",
        " end-class-map\n",
        "!\n",
        "class-map match-any BUSINESS-TC\n",
        " description 'Match medium traffic-class 3'\n",
        " match traffic-class 3\n",
        " end-class-map\n",
        "!\n",
        "policy-map QOS-IN\n",
        " class MGMT\n",
        "  set traffic-class 7\n",
        " !\n",
        " class VOICE\n",
        "  set traffic-class 7\n",
        " !\n",
        " class BUSINESS\n",
        "  set traffic-class 4\n",
        " !\n",
        " class BULK\n",
        "  set traffic-class 3\n",
        " !\n",
        " class IPTV\n",
        "  set traffic-class 6\n",
        " !\n",
        " class class-default\n",
        "  set mpls experimental topmost 0\n",
        "  set traffic-class 6\n",
        "  set dscp 0\n",
        " !\n",
        " end-policy-map\n",
        "!\n",
        "policy-map QOS-OUT\n",
        " class MGMT-TC\n",
        "  priority level 1\n",
        " !\n",
        " class BUSINESS-TC\n",
        "  priority level 3\n",
        " !\n",
        " class BULK-TC\n",
        "  priority level 4\n",
        " !\n",
        " class VOICE-TC\n",
        "  priority level 1\n",
        " !\n",
        " class IPTV-TC\n",
        "  priority level 2\n",
        " !\n",
        " class class-default\n",
        " !\n",
        " end-policy-map\n",
        "!\n"
    ]
    ncs_config_file.writelines(init_config)


def write_bgp_vpnv4_config(bgp_vpnv4_neighbors, ncs_config_file):
    logger = logging.getLogger('write_bgp_vpnv4_config')
    for neighbor in bgp_vpnv4_neighbors:
        logger.info(f'Adding config for iBGP-neighbor {neighbor} (family vpnv4)')
        ncs_config_file.writelines([
            f"router bgp 65000 neighbor {neighbor}\n",
            f"router bgp 65000 neighbor {neighbor} use neighbor-group iBGP\n",
            f"router bgp 65000 neighbor {neighbor} address-family vpnv4 unicast\n"
        ])


def write_vrf_config(vrf_list, ncs_config_file):
    for vrf in vrf_list:
        ncs_config_file.writelines([
            f"vrf {vrf['vrf_name']} \n",
            f"vrf {vrf['vrf_name']} address-family ipv4 unicast\n",
        ])
        for rt in vrf['vrf_rt_import'].split(sep=','):
            ncs_config_file.write(f"vrf {vrf['vrf_name']} address-family ipv4 unicast "
                                  f"import route-target {rt}\n")
        for rt in vrf['vrf_rt_export'].split(sep=','):
            ncs_config_file.write(f"vrf {vrf['vrf_name']} address-family ipv4 unicast "
                                  f"export route-target {rt}\n")
        ncs_config_file.writelines([
            f"router bgp 65000 vrf {vrf['vrf_name']}\n",
            f"router bgp 65000 vrf {vrf['vrf_name']} rd {vrf['vrf_rd']}\n",
            f"router bgp 65000 vrf {vrf['vrf_name']} address-family ipv4 unicast\n",
            f"router bgp 65000 vrf {vrf['vrf_name']} address-family ipv4 unicast "
            f"label mode per-vrf\n",
            f"router bgp 65000 vrf {vrf['vrf_name']} address-family ipv4 unicast "
            f"redistribute connected\n",
            f"router bgp 65000 vrf {vrf['vrf_name']} address-family ipv4 unicast "
            f"redistribute static\n",
        ])


def write_acl_config(acl_list, hostname, ncs_config_file, se_config_file):
    for acl in acl_list:
        if acl.is_on_pe:
            ncs_config_file.write(create_acl_config(acl))
        if acl.is_on_se:
            acl.name = format_acl_name_for_se(acl.name, hostname)
            se_config_file.write(create_acl_config(acl))


def write_aggregations_config(aggregations, esi_template, ncs_config_file):
    logger = logging.getLogger('write_aggregations_config')

    bundle_id = MIN_AGGR_PORT
    for neighbor in sort_aggregations(aggregations):
        if bundle_id > MAX_AGGR_PORT:
            print('ВНИМАНИЕ! Кончились порты для выделения агрегациям.')
            logger.error(f'No more ports for aggregations')
            break
        logger.info(f'GigabitEthernet0/0/0/{bundle_id} is allocated '
                    f'for neighbor {neighbor["neighbor"]}')

        # Физика:
        neighbor['ncs_interface'] = []
        ncs_config_file.writelines([
            f"interface preconfigure GigabitEthernet0/0/0/{bundle_id} "
            f"description -=={neighbor['description']}==-\n",
            f"interface preconfigure GigabitEthernet0/0/0/{bundle_id}\n",
            f"interface preconfigure GigabitEthernet0/0/0/{bundle_id} bundle id "
            f"{bundle_id} mode on\n"])

        # Бандл:
        ncs_config_file.writelines([
            f"interface Bundle-Ether{bundle_id}\n",
            f"interface Bundle-Ether{bundle_id} description "
            f"-=={neighbor['description']}==-\n",
            f"interface Bundle-Ether{bundle_id} mtu {neighbor['mtu']}\n",
            f"interface Bundle-Ether{bundle_id} service-policy output QOS-OUT\n",
            f"interface Bundle-Ether{bundle_id} bundle load-balancing hash dst-ip\n",
            f"interface Bundle-Ether{bundle_id} load-interval 30\n"
        ])
        logger.info('Bundle-Ether{} is created'.format(bundle_id))

        # ESI:
        ncs_config_file.writelines([
            f"evpn interface Bundle-Ether{bundle_id}\n",
            f"evpn interface Bundle-Ether{bundle_id} ethernet-segment\n",
            f"evpn interface Bundle-Ether{bundle_id} ethernet-segment identifier "
            f"type 0 {esi_template.format(bundle_id)}\n"
        ])
        logger.info(f'ESI for Bundle-Ether{bundle_id}: {esi_template.format(bundle_id)}')

        # В словарь с параметрами соседа записываем назначенный порт:
        neighbor['ncs_interface'].append(bundle_id)

        # Если порт-ченнел:
        if neighbor.get('port_channel_interface'):
            bundle_id += 1
            logger.info(f'Adding GigabitEthernet0/0/0/{bundle_id} to '
                        f'Bundle-Ether{bundle_id - 1}')
            ncs_config_file.writelines([
                f"interface preconfigure GigabitEthernet0/0/0/{bundle_id} description "
                f"-=={neighbor['description']}==-\n",
                f"interface preconfigure GigabitEthernet0/0/0/{bundle_id}\n",
                f"interface preconfigure GigabitEthernet0/0/0/{bundle_id} "
                f"bundle id {bundle_id - 1} mode on\n"
            ])
            neighbor['ncs_interface'].append(bundle_id)

        bundle_id += 1


def write_interlinks_config(interlinks, hostname, ncs_config_file):
    logger = logging.getLogger('write_interlinks_config')

    bundle_id = MIN_INTERLINK_PORT
    for neighbor in interlinks:
        # Не обрабатываем межкомплект, если он уходит c другой PE:
        if neighbor['hostname'] != hostname:
            logger.info(f'{hostname} Neighbor {neighbor["neighbor"]} '
                        f'belongs to another PE. Skipping')
            continue
        if bundle_id > MAX_INTERLINK_PORT:
            print('ВНИМАНИЕ! Кончились порты для выделения межкомплектам.')
            logger.error(f'{hostname} No more ports for interlinks')
            break
        logger.info(f'{hostname} TenGigE0/0/0/{bundle_id} is allocated for interlink')
        ncs_config_file.writelines([
            f"interface preconfigure TenGigE0/0/0/{bundle_id} description "
            f"-=={neighbor['description']}==-\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} cdp\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} mtu {neighbor['mtu']}\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} service-policy "
            f"input QOS-IN\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} ipv4 address "
            f"{neighbor['ip']} 255.255.255.252\n"
        ])
        neighbor['ncs_interface'] = [bundle_id]

        bundle_id += 1


def write_uplink_config(uplinks, hostname, ncs_config_file):
    logger = logging.getLogger('write_uplink_config')

    bundle_id = MIN_UPLINK_PORT
    for neighbor in uplinks:
        if neighbor['hostname'] != hostname:  # Eсли аплинк с другой PE
            logger.info(f'{hostname} Neighbor {neighbor["neighbor"]} '
                        f'belongs to another PE. Skipping')
            continue
        if bundle_id > MAX_UPLINK_PORT:
            print('ВНИМАНИЕ! Кончились порты для выделения аплинкам.')
            logger.error(f'{hostname} No more ports for uplinks')
            exit()
        logger.info(f'{hostname} TenGigE0/0/0/{bundle_id} is allocated for '
                    f'neighbor {neighbor["neighbor"]}')
        ncs_config_file.writelines([
            f"interface preconfigure TenGigE0/0/0/{bundle_id} description "
            f"-=={neighbor['description']}==-\n",
            "interface preconfigure TenGigE0/0/0/{bundle_id} cdp\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} mtu {neighbor['mtu']}\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} service-policy "
            f"input QOS-IN\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} service-policy "
            f"output QOS-OUT\n",
            f"interface preconfigure TenGigE0/0/0/{bundle_id} ipv4 address "
            f"{neighbor['ip']} 255.255.255.252\n"
        ])
        neighbor['ncs_interface'] = [bundle_id]

        bundle_id += 1


def write_policies_config(policies, ncs_config_file):
    for policy in policies:
        ncs_config_file.writelines(create_policy(policy))
