import logging
import re
import click
import ipaddress
from config_generator.excel_manager import get_billing_data
from config_generator.connections import get_hostname


def parse_vlan_parameters(string):
    parameters = re.search(r'(^\d+) *(\S+) *\S+ +(.+)', string)
    vlan_id = parameters.group(1)
    vlan_name = format_int_description(parameters.group(2))
    vlan_interfaces = parameters.group(3).replace(' ', '')
    if vlan_interfaces:
        vlan_interfaces = vlan_interfaces.split(',')
    else:
        vlan_interfaces = None
    return vlan_id, vlan_name, vlan_interfaces


def get_vlan_list(hostname, connection, max_num=None):
    """

    :param hostname: 
    :param max_num: parse only <max_num> number of vlan_list
    :param connection:
    :return: Список словарей, содержащих параметры вланов
    """

    logger = logging.getLogger(f'get_vlan_list: {hostname}')
    logger.info('Starting function')

    vlan_possible_states = ['active', 'act/lshut', 'sus/lshut']
    output = connection.send_command('show vlan all-ports')
    vlan_list = []
    i = 0
    for line in output.split(sep='\n'):
        if i == max_num:
            break
        for vlan_state in vlan_possible_states:
            if line.find(vlan_state) != -1:
                vlan_id, vlan_name, interfaces = parse_vlan_parameters(line)
                if interfaces:  # Не добавляем вланы без интерфейсов
                    vlan = {'hostname': hostname,
                            'vlan_id': vlan_id,
                            'vlan_name': vlan_name,
                            'vlan_interfaces': interfaces
                            }
                    vlan_list.append(vlan)
                    break
                else:
                    logger.info(f'Vlan {vlan_id} doesn\'t have interfaces. Skipping')
                i += 1

    return vlan_list


def set_billing_flag(vlan_list, hostname):
    """

    :param vlan_list: список словарей с информацией о вланах на PE,
    :param hostname: Словарь, содержащий параметры для подключения и хостнейм
    :return: None; добавляет в существующий список словарей ключ 'is_in_billing' == bool
    """

    logger = logging.getLogger(f'is_in_billing: {hostname}')
    logger.info('Starting function')

    vlans_in_billing = get_billing_data(hostname)
    for vlan in vlan_list:
        if vlan['vlan_id'] in vlans_in_billing:
            vlan['is_in_billing'] = True
        else:
            vlan['is_in_billing'] = False


def set_mac_flag(vlan_list, hostname, connection):
    """
    :param connection:
    :param vlan_list: список cловарей, содержащих параметры вилана с PE,
    для которых будет проверяться наличие mac-адресов.
    :param hostname: 
    :return: None; добавляет в существующий список словарей ключ 'has_mac' == bool
    """

    logger = logging.getLogger(f'set_mac_flag: {hostname}')
    logger.info('Starting function')

    for vlan in vlan_list:
        if not vlan['is_in_billing']:  # Проверяем вланы, которых нет в биллинге
            output = connection.send_command(f'show mac address-table vlan '
                                             f'{vlan["vlan_id"]}')
            if output.find('dynamic') != -1:
                vlan['has_mac'] = True
            else:
                vlan['has_mac'] = False
        else:
            vlan['has_mac'] = None

    return None


def check_uptime(hostname, connection):
    """
    :return: Выводит на экран предупреждение, если аптайм меньше двух недель
    """
    logger = logging.getLogger(f'set_mac_flag: {hostname}')
    logger.info('Starting function')

    uptime_output = connection.send_command('show version | i uptime')
    if uptime_output.find('weeks') == -1 and uptime_output.find('years') == -1:
        click.echo(
            f'\u001b[31mВНИМАНИЕ:\u001b[0m аптайм {hostname} всего '
            f'"{re.search("uptime is (.*)", uptime_output).group(1)}".\n'
            f'Отсутствие last input может не отображать реальной ситуации.')
        logger.info('Uptime is less than 2 weeks')


def set_last_input_flag(vlan_list, hostname, connection):
    """

    :param hostname: 
    :param vlan_list: Список словарей, содержащих параметры виланов с PE,
        для которых будет проверяться наличие записи "Last input never"
    :param connection: Словарь, содержащий параметры для подключения и хостнейм железки
    :return: None; добавляет в существующий список словарей ключи 
    'hasnt_last_input' = bool, 'is_l2/l3' = str['L2'|'L3']
    """

    logger = logging.getLogger(f'set_last_input_flag: {hostname}')
    logger.info('Starting function')

    for vlan in vlan_list:
        output = connection.send_command(f'show interfaces vlan {vlan["vlan_id"]} '
                                         f'| i Last input')
        if output.find('Invalid input detected') == -1:
            if output.find('Last input never') == -1:
                vlan['hasnt_last_input'] = True
                vlan['is_l2/l3'] = 'L3'
                logger.info(f'{hostname} Vlan: {vlan["vlan_id"]}, {vlan["is_l2/l3"]}-'
                            f'interface, "last input never" is not found')
            else:
                vlan['hasnt_last_input'] = False
                vlan['is_l2/l3'] = 'L3'
                logger.info(f'Vlan: {vlan["vlan_id"]}, {vlan["is_l2/l3"]}-interface, '
                            f'"last input never" is FOUND')
        else:
            vlan['hasnt_last_input'] = False
            vlan['is_l2/l3'] = 'L2'
            logger.info(f'Vlan: {vlan["vlan_id"]}, {vlan["is_l2/l3"]}-interface')

    return None


def set_transferable_flag(vlan_list, hostname):
    """

    :param hostname:
    :param vlan_list: Список словарей, содержащих параметры виланов с PE,
    для которого ищется хотя бы один из флагов 'has_mac', 'hasnt_last_input',
    'is_in_billing', если во влане есть хотя бы один интерфейс.
    :return: None; добавляет в словари ключ 'is_transferable' == bool
    """

    logger = logging.getLogger(f'set_transferable_flag: {hostname}')
    logger.info('Starting function')

    for vlan in vlan_list:
        if (vlan['is_in_billing'] or vlan['has_mac'] or vlan['hasnt_last_input']) \
                and vlan.get('vlan_interfaces'):
            vlan['is_transferable'] = True
            logger.info(f'Vlan {vlan["vlan_id"]} is transferable')
        else:
            vlan['is_transferable'] = False
            logger.info(f'Vlan {vlan["vlan_id"]} is not transferable')

    return None


def format_int_description(string):
    description = re.sub(r'^-{,3}={,3}', '', string)
    description = re.sub(r'={,3}-{,3}$', '', description)
    return description


def format_physint_description(string):
    return 'unnamed' if not string else format_int_description(string)


def format_policy(string):
    policy = string.lower()
    policy = re.sub(r'm(b(ps)*|ps)', 'm', policy)
    policy = re.sub(r'k(b(ps)*|ps)', 'k', policy)
    return policy


def format_vlan_config(vlans):
    """

    :param vlans:
    :return: None: Изменяет список словарей vlan_lists на месте.
    Обрабатываем всевозможные исключительные сценарии.
    """

    logger = logging.getLogger(f'format_vlan_config')
    logger.info('Starting function')

    for vlan in vlans:
        # Форматирование:
        if vlan.get('svi_descr'):
            vlan['svi_descr'] = format_int_description(vlan['svi_descr'])
        if vlan.get('svi_policy_in'):
            vlan['svi_policy_in'] = format_policy(vlan['svi_policy_in'])
        if vlan.get('svi_policy_out'):
            vlan['svi_policy_out'] = format_policy(vlan['svi_policy_out'])

        # Исключения:

        # Если у SVI нет IP, меняем левел на L2:
        if not vlan['svi_ip']:
            vlan['is_l2/l3'] = 'L2'
            logger.warning(f'Interface vlan {vlan["vlan_id"]} hasn\'t ip address '
                           f'actually, changing L3 to L2')

        # Если SVI в vrf WUS, WUS2, BNC-1 или GTS-MGKH - не переносим.
        if vlan.get('svi_vrf') in ['WUS', 'GTS-MGKH', 'WUS2', 'BNC-1']:
            logger.info(f'Interface vlan {vlan["vlan_id"]} is in '
                        f'VRF WUS/WUS2/GTS-MGKH. Setting is_transferable = False')
            vlan['is_transferable'] = False

        # OSPF SVI, если не в vrf MGMT, не переносим (ненужные p2p линки):
        if vlan.get('is_in_ospf') and not vlan.get('svi_vrf') == 'MGMT':
            vlan['is_transferable'] = False
            logger.info(f'Interface vlan {vlan["vlan_id"]} is in ospf, '
                        f'but not in vrf MGMT. Setting is_transferable = False')

    return None


def format_unique_vlan_config(vlans):
    for vlan in vlans:
        # Общий флаг ALARM для форматирования в excel-таблице:
        if vlan.get("alarm_neighbors") or vlan.get("alarm_hsrp") \
                or vlan.get("alarm_subnets") or vlan.get("alarm_intersection"):
            vlan["alarm"] = True
    return vlans


def parse_svi_ip(string):
    try:
        return re.search(r'ip address (\S+ \S+)\n', string).group(1)
    except AttributeError:
        return None


def parse_svi_secondary(string):
    try:
        return re.findall(r'ip address (\S+ \S+) secondary\n', string)
    except AttributeError:
        return None


def parse_int_description(string):
    try:
        return re.search(r'description (.*)\n', string).group(1)
    except AttributeError:
        return None


def parse_svi_vrf(string):
    try:
        return re.search(r'ip vrf forwarding (.*)\n', string).group(1)
    except AttributeError:
        return None


def parse_svi_aclin(string):
    try:
        return re.search(r'ip access-group (.*) in\n', string).group(1)
    except AttributeError:
        return None


def get_svi_aclout(string):
    try:
        return re.search(r'ip access-group (.*) out\n', string).group(1)
    except AttributeError:
        return None


def parse_svi_policyin(string):
    try:
        return re.search(r'service-policy input (.*)\n', string).group(1)
    except AttributeError:
        return None


def parse_svi_policyout(string):
    try:
        return re.search(r'service-policy output (.*)\n', string).group(1)
    except AttributeError:
        return None


def parse_svi_state(string):
    try:
        return re.search(r'\n (shutdown)', string).group(1)
    except AttributeError:
        return None


def parse_svi_mac(string):
    try:
        return re.search(r' (\S+\.\S+\.\S+)', string).group(1)
    except AttributeError:
        return None


def get_svi_config(vlan_list, hostname, connection):
    """

    :param hostname: str, хостнейм железки
    :param vlan_list: list, cписок словарей, содержащий параметры виланов с PE.
    :param connection: Подключение netmiko
    :return: None; добавляет в существующий список словарей ключи
    'svi_descr', 'svi_vrf', 'svi_ip', 'svi_ip_secondary', 'svi_acl_in', 'svi_acl_out',
    'svi_policy_in', 'svi_policy_out', 'svi_admin_state'.
    Если какой-либо параметр отсутствует, ключу соответствует значение None.
    """

    logger = logging.getLogger(f'get_svi_config: {hostname}')
    logger.info('Starting function')

    SVI_KEYS = ['svi_ip', 'svi_ip_secondary', 'svi_descr', 'svi_vrf', 'svi_acl_in',
                'svi_acl_out', 'svi_policy_in', 'svi_policy_out', 'svi_admin_state']

    for vlan in vlan_list:
        if vlan['is_l2/l3'] == 'L3':
            output = connection.send_command(f'show run interface vlan {vlan["vlan_id"]}')
            ip = parse_svi_ip(output)
            ip_secondary = parse_svi_secondary(output)
            description = parse_int_description(output)
            vrf = parse_svi_vrf(output)
            acl_in = parse_svi_aclin(output)
            acl_out = get_svi_aclout(output)
            policy_in = parse_svi_policyin(output)
            policy_out = parse_svi_policyout(output)
            admin_state = parse_svi_state(output)

            parameters = [ip, ip_secondary, description, vrf, acl_in, acl_out,
                          policy_in, policy_out, admin_state]

            for key in SVI_KEYS:
                vlan[key] = parameters[SVI_KEYS.index(key)]
                if not vlan[key]:
                    logger.warning(f'SVI {vlan["vlan_id"]}\'s parameter {key} '
                                   f'hasn\'t been found')
        else:
            for key in SVI_KEYS:
                vlan[key] = None

    return None


def get_svi_mac(vlan_list, hostname, connection):
    """

    :param vlan_list: Список словарей, содержащий параметры виланов с PE,
    для которых будут парсится mac-адреса.
    :param hostname: хостнейм железки
    :param connection: подключение netmiko
    :return: svi_mac: мак, используемый всеми SVI
    """

    logger = logging.getLogger(f'get_svi_mac: {hostname}')
    logger.info('Starting function')

    # Достаем мак из любого первого SVI без HSRP:

    for vlan in vlan_list:
        if not vlan.get('is_in_hsrp'):
            logger.info(f'Trying to get SVI {vlan["vlan_id"]}\'s mac')
            output = connection.send_command(f'show mac address-table vlan '
                                             f'{vlan["vlan_id"]} | i No           '
                                             f'-   Router')
            for line in output.split(sep='\n'):
                svi_mac = parse_svi_mac(line)
                if not svi_mac:
                    continue
                logger.info(f'Using SVI {vlan["vlan_id"]}\'s mac as default: {svi_mac}')
                return svi_mac


def set_svi_mac(vlan_list, hostname, connection):
    """

    :param connection:
    :param hostname:
    :param vlan_list: Два списка словарей, содержащих параметры виланов с обеих PE,
    в которые будет добавлен ключ 'svi_mac'
    :return:
    """

    logger = logging.getLogger(f'set_svi_mac: {hostname}')
    logger.info('Starting function')

    svi_default_mac = get_svi_mac(vlan_list, hostname, connection)
    logger.info(f'Default SVI-mac is {svi_default_mac}')

    # Добавляем в словари с инфо о вланах ключ 'svi_mac':

    for vlan in vlan_list:
        vlan['svi_mac'] = svi_default_mac

    return None


def parse_physical_int_parameters(string):
    output = re.search(r'(\S+) +((?:up)|(?:down)|(?:admin down)|(?:deleted)) +(\S+) '
                       r'+(.*)', string)
    try:
        interface = output.group(1)
    except AttributeError:
        interface = None
    try:
        status = output.group(2)
    except AttributeError:
        status = None
    try:
        description = output.group(4)
    except AttributeError:
        description = None

    return interface, status, description


def get_portchannel_members(connection, interface):
    output = connection.send_command(f'show etherchannel {interface.replace("Po", "")} '
                                     f'port-channel')
    member_list = []
    for line in output.split(sep='\n'):
        try:
            member = re.search(r'\d +\S\S +(\S\S\d+/\d+) ', line).group(1)
            member_list.append(member)
        except AttributeError:
            continue
    return member_list


def set_portchannel_flag(interfaces):
    for interface in interfaces:
        if interface['name'].startswith('Po'):
            interface['port_channel_interface'] = True


def get_portchannels(connection, interfaces):
    portchannels = []
    for interface in interfaces:
        if interface.get('port_channel_interface'):
            portchannel_members = get_portchannel_members(connection, interface['name'])
            portchannel = {'name': interface['name'],
                           'interfaces': portchannel_members,
                           'members_amount': len(portchannel_members)
                           }
            portchannels.append(portchannel)
    return portchannels


def mark_portchannel_members(connection, interfaces):
    portchannels = get_portchannels(connection, interfaces)
    for interface in interfaces:
        for portchannel in portchannels:
            if interface['name'] in portchannel['interfaces']:
                interface['port_channel_member'] = portchannel['name']


def get_physint_list(hostname, connection):
    """

    :param hostname:
    :param connection: Словарь, содержащий параметры для подключения и хостнейм железки
    :return: Список словарей, содержащих инфу о интерфейсах с ключами
    'interface', 'status', 'protocol', 'description' = str
    """

    logger = logging.getLogger(f'get_physical_int_list: {hostname}')
    logger.info('Starting function')

    output = connection.send_command('show interfaces description')
    interfaces = []
    for line in output.split(sep='\n'):
        if re.search(r'^Te|^Gi|^Po', line):
            name, status, description = parse_physical_int_parameters(line)
            # Рассматриваются интерфейсы без сабиков в UP:
            if not re.search(r'\.', name) and "down" not in status:
                interface = {'hostname': hostname,
                             'name': name,
                             'status': status,
                             'description': format_physint_description(description)
                             }
                interfaces.append(interface)

    return interfaces


def parse_physint_ip(string):
    _, ip, *_ = string.split()
    return ip if ip != 'unassigned' else None


def add_physint_level(interfaces, hostname, connection):
    """

    :param hostname:
    :param interfaces: Список словарей, содержащих инфу о физических интерфейсах с PE
    :param connection: Словарь, содержащий параметры для подключения и хостнейм железки
    :return: Список обновленных словарей с добавленными ключами 'is_l2/l3','ip' = str
    """

    logger = logging.getLogger(f'get_physical_int_list: {hostname}')
    logger.info('Starting function')

    for interface in interfaces:
        output = connection.send_command(f'show ip interface brief {interface["name"]}')
        for line in output.split(sep='\n'):
            if line and not line.startswith('Interface'):  # Не обрабатываем хлам
                interface['ip'] = parse_physint_ip(line)
                if interface['ip']:
                    logger.info(f'Interface {interface["name"]} is L3')
                    interface['is_l2/l3'] = 'L3'
                else:
                    logger.info(f'Interface {interface["name"]} is L2')
                    interface['is_l2/l3'] = 'L2'


def parse_physint_mtu(string):
    try:
        return re.search(r'MTU (\d+) bytes', string).group(1)
    except AttributeError:
        return None


def add_physint_mtu(interfaces, hostname, connection):
    """

    :param connection:
    :param hostname:
    :param interfaces: Список словарей, содержащих инфу о физических интерфейсах с PE
    :return: Список обновленных словарей с добавленным ключом 'mtu'
    """
    logger = logging.getLogger(f'get_physical_int_list: {hostname}')
    logger.info('Starting function')

    for interface in interfaces:
        output = connection.send_command(f'show interfaces {interface["name"]} | i MTU')
        interface['mtu'] = parse_physint_mtu(output)
        logger.info(f'Interface {interface["name"]}\'s MTU size is {interface["mtu"]}')


def add_physint_role(interfaces):
    """

    :param interfaces:
    :return:
    """

    logger = logging.getLogger(f'get_physical_int_list')
    logger.info('Starting function')
    for interface in interfaces:
        if interface['is_l2/l3'] == 'L2':
            interface['role'] = 'aggregation'
        # Если в имени соседа то же самое имя PE, то это межкомплект:
        elif interface['hostname'][:-3] in interface['neighbor']:
            interface['role'] = 'interlink'
        else:
            interface['role'] = 'uplink'
        logger.info(
            f'{interface["hostname"]} Interface {interface["name"]} '
            f'has been determined as {interface["role"]}'
        )


def parse_neighbor_from_cdp(string):
    try:
        return re.search(r'Device ID: (\S+)', string).group(1)
    except AttributeError:
        return None


def parse_neighbor_from_descr(string):
    try:
        description = re.search(r'(\d+\.\d+\.\d+\.\d+)', string).group(1)
        return format_int_description(description)
    except AttributeError:
        return None


def add_neighbors(interfaces, hostname, connection):
    """

    :param hostname:
    :param interfaces:
    :param connection:
    :return: Идентификатор (имя) соседа на физическом линке
    """
    logger = logging.getLogger(f'add_neighbors: {hostname}')
    logger.info('Starting function')

    for interface in interfaces:
        output = connection.send_command(
            f'show cdp neighbor {interface["name"]} detail | i Device')
        name = parse_neighbor_from_cdp(output)
        if name:
            interface['neighbor'] = name
            logger.info(f'Interface {interface["name"]} has CDP neighbor: '
                        f'{interface["neighbor"]}')
        else:
            # Если CDP нет, берем IP из дескрипшена:
            name = parse_neighbor_from_descr(interface['description'])
            if name:
                interface['neighbor'] = name
                logger.info(f'Interface {interface["name"]} HASN\'T CDP neighbor. '
                            f'Neighbor ID has been extracted from description: '
                            f'{interface["neighbor"]}')
            else:
                # Иначе используем сам дескрипшен:
                interface['neighbor'] = interface['description']
                interface['alarm'] = True
                interface['comment'] = 'Проверить имя соседа;'
                logger.warning(f'Interface {interface["name"]}\'s neighbor name can\'t '
                               f'be extracted. Description will be used as '
                               f'Neighbor ID: {interface["neighbor"]}')


def add_comment(dictionary, value):
    if dictionary.get('comment'):
        dictionary['comment'] += value
    else:
        dictionary['comment'] = value


def get_neighbor(interface, phys_interfaces):
    logger = logging.getLogger(f'get_neighbor')
    logger.info('Starting function')

    for phys_interface in phys_interfaces:
        if interface == phys_interface['name'] and phys_interface.get('neighbor'):
            return phys_interface.get('neighbor')


def get_vlan_neighbors(vlan, phys_interfaces):
    neighbors = []
    for interface in vlan['vlan_interfaces']:
        neighbors.append(get_neighbor(interface, phys_interfaces))
    return neighbors


def get_alarmed_physint(phys_interfaces):
    """Return list of physical interfaces with alarm flag"""
    alarmed_physint = []
    for interface in phys_interfaces:
        if interface.get('alarm'):
            alarmed_physint.append(interface['neighbor'])
    return alarmed_physint


def has_alarmed_neighbors(neighbors, phys_interfaces):
    alarmed_physint = get_alarmed_physint(phys_interfaces)
    if isinstance(neighbors, list):
        for neighbor in neighbors:
            if neighbor in alarmed_physint:
                return True
    else:  # Костыль?
        if neighbors in alarmed_physint:
            return True
    return False


def has_nonexistent_neighbors(neighbors):
    if isinstance(neighbors, list):
        return True if None in neighbors else False
    else:
        return True if neighbors is None else False


def clear_nonexistent_neighbors(neighbors):
    return list(filter(lambda x: x is not None, neighbors))


def add_neighbors_to_vlans(vlans, phys_interfaces):
    """

    :param vlans:
    :param phys_interfaces:
    :return: None, добавляет ключ 'neighbors', содержащий список соседей,
    в сторону которых разбанен влан
    """

    logger = logging.getLogger(f'add_neighbors_to_vlans')
    logger.info('Starting function')

    for vlan in vlans:
        vlan['neighbors'] = get_vlan_neighbors(vlan, phys_interfaces)
        logger.info(f'{vlan["hostname"]} Vlan {vlan["vlan_id"]} '
                    f'neighbor list: {vlan["neighbors"]}'
                    )
        if has_nonexistent_neighbors(vlan['neighbors']):
            vlan['neighbors'] = clear_nonexistent_neighbors(vlan['neighbors'])
            vlan['alarm_neighbors'] = True
            add_comment(vlan, 'Удален несуществующий сосед;')
        if has_alarmed_neighbors(vlan['neighbors'], phys_interfaces):
            vlan['alarm_neighbors'] = True
            logger.warning(f'{vlan["hostname"]} Vlan {vlan["vlan_id"]}: '
                           f'Some neighbors in vlan have ALARM flag.')
            add_comment(vlan, 'Проверить имена соседей;')


def has_mutual_neighbor(vlan1, vlan2):
    """

    :param vlan1:
    :param vlan2:
    :return:
    """

    logger = logging.getLogger(f'has_mutual_neighbor {vlan1["vlan_id"]}')
    logger.info('Starting function')

    mutual_neighbors = set(vlan1['neighbors']) & set(vlan2['neighbors'])
    if mutual_neighbors:
        logger.info(f'Vlan {vlan1["vlan_id"]}: Mutual L2-neighbors are found: '
                    f'{mutual_neighbors}\n')
        return True
    else:
        logger.info(f'Vlan {vlan1["vlan_id"]}: Mutual L2-neighbor HASN\'T found')
        return False


def merge_neighbors(vlan1, vlan2):
    """

    :param vlan1:
    :param vlan2:
    :return: set, объединенный список соседей для влана с обеих PE
    """

    logger = logging.getLogger(f'merge_neighbors {vlan1["vlan_id"]}')
    logger.info('Starting function')

    merged_neighbors = set(vlan1['neighbors']) | set(vlan2['neighbors'])

    return list(merged_neighbors)


def get_unique_vrf_names(vlans):
    vrf_names = set()
    for vlan in vlans:
        if vlan['svi_vrf']:
            vrf_names.add(vlan['svi_vrf'])
    return vrf_names


def parse_vrf_rd(string):
    try:
        return re.search(r'rd (\d+:\d+)', string).group(1)
    except AttributeError:
        return None


def parse_rt_export(string):
    result = re.findall(r'route-target export (\d+:\d+)', string)
    return result if result else None


def parse_rt_import(string):
    result = re.findall(r'route-target import (\d+:\d+)', string)
    return result if result else None


def get_vrf_parameters(vlans, hostname, connection):
    """

    :param vlans: Список словарей, содержащих инфо о вланах с PE
    :param hostname:
    :param connection:
    :return: Список словарей с ключами 'hostname','vrf_name' и 'vrf_rd' = str,
    vrf_rt_export и vrf_rt_import = list
    """

    logger = logging.getLogger(f'get_vrf_parameters {hostname}')
    logger.info('Starting function')

    unique_vrf_names = get_unique_vrf_names(vlans)
    vrf_list = []  # Список словарей, содержащих данные о VRFах

    for vrf_name in unique_vrf_names:
        vrf = {}  # Словарь, содержащий данные о VRF
        output = connection.send_command(f'show run vrf {vrf_name}')
        vrf['hostname'] = hostname
        vrf['vrf_name'] = vrf_name
        vrf['vrf_rd'] = parse_vrf_rd(output)
        vrf['vrf_rt_export'] = parse_rt_export(output)
        vrf['vrf_rt_import'] = parse_rt_import(output)
        vrf_list.append(vrf)
        logger.info(
            f'VRF {vrf["vrf_name"]} rd: {vrf["vrf_rd"]}, '
            f'rt_export: {vrf["vrf_rt_export"]}, rt_import: {vrf["vrf_rt_import"]}'
        )

    return vrf_list


def parse_xc_parameters(string):
    parameters = re.search(r'\S+ +\S+ +(\S+):(\d+).+ '
                           r'(\d+\.\d+\.\d+\.\d+):(\d+) *(\S+)', string)
    try:
        source_port = parameters.group(1)
    except AttributeError:
        source_port = None
    try:
        dot1q = parameters.group(2)
    except AttributeError:
        dot1q = None
    try:
        remote_ip = parameters.group(3)
    except AttributeError:
        remote_ip = None
    try:
        pwid = parameters.group(4)
    except AttributeError:
        pwid = None
    try:
        state = parameters.group(5)
    except AttributeError:
        state = None

    return source_port, dot1q, remote_ip, pwid, state


def get_xc_list(connection):
    """

    :param connection:
    :return: Список словарей, содержащих параметры XC c ключами
    'hostname', 'source_port', 'dot1q', 'remote_ip', 'pwid', 'state'
    """
    logger = logging.getLogger(f'get_xc_list')
    logger.info('Starting function')

    # XC, находящиеся в этом статусе, будут добавлены в таблицу.
    # Возможные статусы:
    #   UP=Up       DN=Down            AD=Admin Down      IA=Inactive
    #   SB=Standby  HS=Hot Standby     RV=Recovering      NH=No Hardware

    XC_POSSIBLE_STATES = ['UP', 'DN', 'AD', 'IA', 'SB', 'RV']

    hostname = get_hostname(connection)
    output = connection.send_command('show xc all')
    xc_list = []
    for line in output.split(sep='\n'):
        for state in XC_POSSIBLE_STATES:
            if line.endswith(state):
                source_port, dot1q, remote_ip, pwid, state = parse_xc_parameters(line)
                xc = {'hostname': hostname,
                      'dot1q': dot1q,
                      'source_port': source_port,
                      'remote_ip': remote_ip,
                      'pwid': pwid,
                      'state': state
                      }
                xc_list.append(xc)

    return xc_list


def parse_xc_source_int(string):
    try:
        return re.search(r'(((?:Po)|(?:Gi)|(?:Te)).*)\.', string).group(1)
    except AttributeError:
        return None


def get_xc_source_neighbor():
    pass


def add_xc_source_neighbors(xc_list, phys_interfaces):
    """

    :param xc_list:
    :param phys_interfaces:
    :return:
    """
    logger = logging.getLogger(f'add_xc_source_neighbors')
    logger.info('Starting function')

    for xc in xc_list:
        xc_source_interface = parse_xc_source_int(xc['source_port'])
        if not xc_source_interface:
            xc['alarm'] = True
            continue
        xc['source_neighbor'] = get_neighbor(xc_source_interface, phys_interfaces)
        if has_nonexistent_neighbors(xc['source_neighbor']):
            xc['alarm'] = True
            add_comment(xc, 'Несуществующий сосед;')
        if has_alarmed_neighbors(xc['source_neighbor'], phys_interfaces):
            xc['alarm'] = True
            add_comment(xc, 'Необходимо проверить имя соседа;')

    return None


def add_xc_source_int_description(xc_list, connection):
    """

    :param connection:
    :param hostname:
    :param xc_list:
    :return:
    """

    logger = logging.getLogger(f'add_xc_source_int_description')
    logger.info('Starting function')

    for xc in xc_list:
        output = connection.send_command(f'sh run int {xc["source_port"]}')
        description = parse_int_description(output)
        if description:
            xc['source_int_description'] = format_int_description(description)
        else:
            logger.info(f'Description for {xc["source_port"]} hasn\'t found')


def are_in_same_subnet(vlan1, vlan2):
    """

    :param vlan1:
    :param vlan2:
    :return:
    """

    logger = logging.getLogger(f'are_in_same_subnet')
    logger.info(f'Starting function for vlan {vlan1["vlan_id"]}')

    vlan1_ip = ipaddress.ip_interface(vlan1['svi_ip'].replace(' ', '/'))
    vlan2_ip = ipaddress.ip_interface(vlan2['svi_ip'].replace(' ', '/'))
    logger.info(f'Interface vlan {vlan1["vlan_id"]}, '
                f'PE-01: {vlan1["svi_ip"]} '
                f'PE-02: {vlan2["svi_ip"]}\n'
                )

    return True if vlan1_ip.network == vlan2_ip.network else False


def are_both_l3(vlan1, vlan2):
    return vlan1['is_l2/l3'] == vlan2['is_l2/l3'] == 'L3'


def get_vlanid_list(vlan_list):
    vlanid_list = []
    for vlan in vlan_list:
        vlanid_list.append(vlan['vlan_id'])
    return vlanid_list


def get_repeated_vlan_ids(vlans):
    common_vlanid_list = []
    vlanid_list = []
    for vlan_id in get_vlanid_list(vlans):
        if vlan_id not in vlanid_list:
            vlanid_list.append(vlan_id)
        else:
            common_vlanid_list.append(vlan_id)
    return common_vlanid_list


def get_different_vlan_ids(vlans):
    vlanid_list = get_vlanid_list(vlans)
    common_vlanid_list = get_repeated_vlan_ids(vlans)
    return set(vlanid_list) - set(common_vlanid_list)


def has_transferable_duplicate(nontransferable_vlan, vlan_list):
    for vlan in vlan_list:
        if vlan['vlan_id'] == nontransferable_vlan['vlan_id'] and vlan['is_transferable']:
            return True
    return False


def get_nontransferrable_vlan_ids(vlan_list):
    repeated_ids = get_repeated_vlan_ids(vlan_list)
    single_ids = get_different_vlan_ids(vlan_list)
    nontransferable_ids = []
    for vlan in vlan_list:
        if vlan['vlan_id'] in single_ids and not vlan['is_transferable']:
            nontransferable_ids.append(vlan['vlan_id'])
        elif vlan['vlan_id'] in repeated_ids and not vlan['is_transferable']:
            if not has_transferable_duplicate(vlan, vlan_list):
                nontransferable_ids.append(vlan['vlan_id'])
    return nontransferable_ids


def search(_list, **kwargs):
    """Return list of dicts, which contain key=value pairs from kwargs"""
    result = []
    for element in _list:
        match = 0
        for key in kwargs.keys():
            if element.get(key) == kwargs[key]:
                match += 1
            else:
                break
        if match == len(kwargs.keys()):
            result.append(element)
    return result if result else None


def merge_vlans(vlan1, vlan2):
    logger = logging.getLogger(f'merge_vlans: VLAN {vlan1["vlan_id"]}')
    logger.info(f'Starting function')

    merged_vlan = vlan1
    merged_vlan['neighbors'] = merge_neighbors(vlan1, vlan2)
    if vlan1.get('admin_state') != vlan2.get('admin_state'):
        merged_vlan['admin_state'] = None
        logger.info(f'Vlan {vlan2["vlan_id"]}: Changing admin_state to UP')
    if vlan1['is_l2/l3'] != vlan2['is_l2/l3']:
        merged_vlan['is_l2/l3'] = 'L3'
        logger.info(f'Vlan {vlan2["vlan_id"]}: Changing L2 to L3')
    merged_vlan['is_merged'] = True

    return merged_vlan


def get_unique_vlans(vlans):
    """

    :param vlans: 
    :return:
    """
    logger = logging.getLogger(f'get_unique_vlans')
    logger.info(f'Starting function')

    unique_vlans = []
    repeated_ids = get_repeated_vlan_ids(vlans)
    single_ids = get_different_vlan_ids(vlans)
    nontransferrable_ids = get_nontransferrable_vlan_ids(vlans)

    # Уникальные вланы:
    for vlan_id in single_ids:
        if vlan_id not in nontransferrable_ids:
            vlan, = search(vlans, vlan_id=vlan_id)
            unique_vlans.append(vlan)

    # Повторяющиеся вланы:
    for vlan_id in repeated_ids:
        if vlan_id not in nontransferrable_ids:
            vlan1, vlan2 = search(vlans, vlan_id=vlan_id)
            # Все повторяющиеся вланы - L3:
            if are_both_l3(vlan1, vlan2):
                logger.info(f'Vlan {vlan1["vlan_id"]}: Both SVIs are L3. '
                            f'Checking if they\'re in the same subnet')
                # Повторяющиеся вланы в одной подсети:
                if are_in_same_subnet(vlan1, vlan2):
                    unique_vlans.append(merge_vlans(vlan1, vlan2))
                    logger.info(f'Vlan {vlan1["vlan_id"]}: both are in the same subnet. '
                                f'Merging.')
                # Повторяющиеся вланы в разных подсетях:
                else:
                    vlan1['alarm_subnets'] = vlan2['alarm_subnets'] = True
                    add_comment(vlan2, f'IP в разных подсетях (PE-01:{vlan1["svi_ip"]}, '
                                       f'PE-02:{vlan2["svi_ip"]});')
                    unique_vlans.append(vlan1)
                    unique_vlans.append(vlan2)
                    logger.warning(
                        f'Vlan {vlan1["vlan_id"]}: SVIs are in different '
                        f'subnets. Setting alarm_subnets flag'
                    )
            # Повторяющиеся вланы - разных уровней:
            else:
                logger.info(f'Vlan {vlan2["vlan_id"]}: SVI on PE-01 is '
                            f'{vlan1["is_l2/l3"]}, SVI on PE-02 is {vlan2["is_l2/l3"]}. '
                            f'Checking mutual neighbors on L2'
                            )
                # Пересекаются на L2:
                if has_mutual_neighbor(vlan1, vlan2):
                    merge_vlans(vlan1, vlan2)
                    logger.info(f'Vlan {vlan2["vlan_id"]}: '
                                f'Mutual neighbors are found. Merging')

                else:
                    # Не пересекаются:
                    vlan1['alarm_intersection'] = vlan2['alarm_intersection'] = True
                    add_comment(vlan2, f'Влан на PE-01: {vlan1["is_l2/l3"]}, на PE-02: '
                                       f'{vlan2["is_l2/l3"]}. Нет пересечений на L2')
                    unique_vlans.append(vlan1)
                    unique_vlans.append(vlan2)
                    logger.warning(f'Vlan {vlan2["vlan_id"]}: Duplicated vlan is found. '
                                   f'Setting alarm_intersection flag'
                                   )

    return unique_vlans


def get_neighbor_list(interfaces):
    neighbor_list = []
    for interface in interfaces:
        if not interface.get('port_channel_member'):  # Добавляются только сами PO
            neighbor_list.append(interface['neighbor'])
    return neighbor_list


def get_repeated_neighbors(interfaces):
    repeated_neighbors = set()
    unique_neighbors = []
    for neighbor in get_neighbor_list(interfaces):
        if neighbor not in unique_neighbors:
            unique_neighbors.append(neighbor)
        else:
            repeated_neighbors.add(neighbor)
    return list(repeated_neighbors)


def get_single_neighbors(interfaces):
    neighbors = get_neighbor_list(interfaces)
    repeated_neighbors = get_repeated_neighbors(interfaces)
    return set(neighbors) - set(repeated_neighbors)


def get_unique_neighbors(phys_interfaces):
    """

    :param phys_interfaces:
    :return:
    """
    logger = logging.getLogger(f'get_unique_neighbors')
    logger.info(f'Starting function')

    unique_neighbors = []
    single_neighbors = get_single_neighbors(phys_interfaces)
    repeated_neighbors = get_repeated_neighbors(phys_interfaces)

    for neighbor_name in single_neighbors:
        interface, *_ = search(phys_interfaces,
                               neighbor=neighbor_name,
                               port_channel_member=None
                               )
        if interface['is_l2/l3'] == 'L3':
            logger.info(f'Adding {interface["neighbor"]} (UPLINK)')
        else:
            interface['link_amount'] = 1
            logger.info(f'{interface["neighbor"]} has only 1 link (AGGREGATION)')
        unique_neighbors.append(interface)

    for neighbor_name in repeated_neighbors:
        interfaces = search(phys_interfaces,
                            neighbor=neighbor_name,
                            port_channel_member=None
                            )
        interface, *_ = interfaces
        if interface['is_l2/l3'] == 'L3':
            logger.info('Adding {} (UPLINK or INTERLINK)'.format(interface['neighbor']))
            unique_neighbors.append(interface)
        else:
            link_amount = len(interfaces)
            interface['link_amount'] = link_amount
            unique_neighbors.append(interface)
            logger.info(f'{interface["neighbor"]} has {link_amount} links (AGGREGATION)')

    return unique_neighbors


def get_unique_vrf_list(vrf_list):
    """

    :param vrf_list:
    :return:
    """

    logger = logging.getLogger(f'get_unique_vrf_list')
    logger.info(f'Starting function')

    unique_vrf_list = []
    unique_vrf_rd_list = []

    for vrf in vrf_list:
        if vrf['vrf_rd'] not in unique_vrf_rd_list:
            unique_vrf_list.append(vrf)
            unique_vrf_rd_list.append(vrf['vrf_rd'])

    return unique_vrf_list


def get_vrf_with_eigrp_list(hostname, connection):
    logger = logging.getLogger(f'get_unique_vrf_list {hostname}')
    logger.info(f'Starting function')

    vrf_list = []
    output = connection.send_command('show run | sec router eigrp')
    for line in output.split(sep='\n'):
        try:
            vrf_with_eigrp = re.search(r'address-family ipv4 vrf (\S+)', line).group(1)
            vrf_list.append(vrf_with_eigrp)
        except AttributeError:
            continue

    logger.info('VRF list: {}'.format(vrf_list))

    return vrf_list


def set_eigrp_flag(vlans, hostname, connection):
    """

    :param connection: 
    :param hostname: 
    :param vlans: 
    :return: None, add is_in_eigrp flag to dictionaries
    """

    logger = logging.getLogger(f'set_eigrp_flag {hostname}')
    logger.info(f'Starting function')

    vrf_with_eigrp_list = get_vrf_with_eigrp_list(hostname, connection)
    for vlan in vlans:
        if vlan.get('svi_vrf') in vrf_with_eigrp_list:
            vlan['is_in_eigrp'] = True
            add_comment(vlan, 'Интерфейс в EIGRP; ')
            logger.info(
                f'Interface vlan {vlan["vlan_id"]} has been marked as eigrp-member')


def parse_hsrp_ips(string):
    return re.findall(r'standby \d+ ip (\d+\.\d+\.\d+\.\d+(?: secondary)*)', string)


def get_hsrp_parameters(hsrp_interface, hostname, connection):
    """

    :param connection:
    :param hostname:
    :param hsrp_interface:
    :return:
    """
    logger = logging.getLogger(f'get_hsrp_parameters {hostname}')
    logger.info(f'Starting function')

    output = connection.send_command(f'show run int vlan {hsrp_interface} '
                                     f'| i standby.*ip')
    hsrp_ip_list = parse_hsrp_ips(output)
    parameters = {'hsrp_interface': hsrp_interface, 'hsrp_ip_secondary': []}

    for ip in hsrp_ip_list:
        if 'secondary' in ip:
            parameters['hsrp_ip_secondary'].append(ip.replace(' secondary', ''))
        elif not parameters.get('hsrp_ip'):
            parameters['hsrp_ip'] = ip
        # Когда на интерфейсе несколько hsrp групп, второй ip записываем в secondary:
        else:
            parameters['hsrp_ip_secondary'].append(ip)
    logger.info(
        f'Vlan {parameters["hsrp_interface"]}: virtual ip is {parameters["hsrp_ip"]}, '
        f'secondary addresses are: {parameters["hsrp_ip_secondary"]}\n'
    )

    return parameters


def format_hsrp_interface(string):
    return re.sub('Vl', '', string)


def parse_hsrp_interfaces(string):
    hsrp_interfaces = []
    for line in string.split(sep='\n'):
        if line.startswith('Vl'):
            interface, *_ = line.split()
            interface = format_hsrp_interface(interface)
            if interface not in hsrp_interfaces:
                hsrp_interfaces.append(interface)

    return hsrp_interfaces


def get_mask(prefix):
    return prefix.split()[1]


def change_svi_ip_to_hsrp_ip(vlan, hsrp_parameters):
    logger = logging.getLogger(f'change_svi_ip_to_hsrp_ip {vlan["vlan_id"]}')
    logger.info(f'Starting function')

    # Изменяем SVI IP на виртуальный адрес hsrp, используя старую маску:
    vlan['svi_ip'] = hsrp_parameters['hsrp_ip'] + ' ' + get_mask(vlan['svi_ip'])
    logger.info(
        f'Changing SVI {vlan["vlan_id"]}\'s ip {vlan["svi_ip"]} to hsrp virtual ip '
        f'{hsrp_parameters["hsrp_ip"]}'
    )
    # Изменяем secondary:
    if hsrp_parameters['hsrp_ip_secondary']:
        for hsrp_ip_secondary in hsrp_parameters['hsrp_ip_secondary']:
            index = hsrp_parameters['hsrp_ip_secondary'].index(hsrp_ip_secondary)
            vlan['svi_ip_secondary'][index] = \
                hsrp_ip_secondary + ' ' + get_mask(vlan['svi_ip_secondary'])
            logger.info(
                f'Changing SVI {vlan["vlan_id"]}\'s secondary ip '
                f'{vlan["svi_ip_secondary"][index]} to hsrp '
                f'virtual ip {hsrp_ip_secondary}'
            )


def set_hsrp_flag(vlans, hostname, connection):
    """

    :param vlans:
    :param hostname:
    :param connection:
    :return:
    """

    logger = logging.getLogger(f'set_hsrp_flag {hostname}')
    logger.info(f'Starting function')

    parameters_list = []  # Список словарей с 'hsrp_interface', 'hsrp_ip', 'alarm'

    output = connection.send_command('show standby brief')
    hsrp_interfaces = parse_hsrp_interfaces(output)
    logger.info('Resulted SVIs with HSRP list: {}'.format(hsrp_interfaces))

    for interface in hsrp_interfaces:
        parameters_list.append(get_hsrp_parameters(interface, hostname, connection))

    # Отмечаем флагом is_in_hsrp интерфейсы из списка svi_numbers_with_hsrp:

    for vlan in vlans:
        if vlan['vlan_id'] in hsrp_interfaces:
            vlan['is_in_hsrp'] = True
            logger.info('SVI {} in HSRP'.format(vlan['vlan_id']))
            for parameters in parameters_list:
                if parameters['hsrp_interface'] == vlan['vlan_id']:
                    change_svi_ip_to_hsrp_ip(vlan, parameters)


def set_ospf_flag(vlans, hostname, connection):
    """

    :param hostname: 
    :param vlans:
    :param connection:
    :return:
    """

    logger = logging.getLogger(f'set_hsrp_flag {hostname}')
    logger.info(f'Starting function')

    ospf_interfaces = []  # Список SVI, включенных в OSPF

    output = connection.send_command('show ip ospf interface brief')

    for line in output.split(sep='\n'):
        if line.startswith('Vl'):  # Не рассматриваем физические интерфейсы
            ospf_interfaces.append(re.search(r'Vl(\d+)', line).group(1))
    for vlan in vlans:
        if vlan['vlan_id'] in ospf_interfaces:
            vlan['is_in_ospf'] = True
            logger.info(f'SVI {vlan["vlan_id"]} is in OSPF')


def get_acl_list(connection):
    """

    :param connection:
    :return:
    """

    output = connection.send_command('sh run partition access-list')
    acl_dict = {}  # Cловарь, ключами которых являются названия ACL

    for line in output.split(sep='\n'):
        # Стандартный и расширенный ACL:
        if line.startswith('ip access-list'):
            acl_name = re.search(r'ip access-list (?:standard|extended) '
                                 r'(\S+)', line).group(1)
            acl_dict[acl_name] = []
        elif line.startswith(' permit') or line.startswith(' deny'):
            acl_dict[acl_name].append(
                line.replace(' permit', 'permit').replace(' deny', 'deny'))
        # Нумерованный ACL:
        elif line.startswith('access-list'):
            numbered_output = re.search(r'access-list (?P<name>\d+) (?P<rule>.*)', line)
            if not acl_dict.get(numbered_output.group('name')):
                acl_dict[numbered_output.group('name')] = []
            acl_dict[numbered_output.group('name')].append(
                numbered_output.group('rule'))
        else:
            continue

    return acl_dict


def merge_lists(data):
    """

    :param data: list of lists
    :return: flatten list
    """
    result = data[0].copy()
    for i in range(1, len(data)):
        result.extend(data[i])
    return result
