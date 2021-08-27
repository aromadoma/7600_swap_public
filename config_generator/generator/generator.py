from getpass import getpass
import re
import os
import click
import ipaddress
import logging
from config_generator.fstools import get_homedir_path, get_preparing_path
from config_generator.connections import connect, get_hostname
from config_generator.excel_manager import load_data_from_table
from config_generator.parameters import get_se_loopbacks30, get_ios_neighbors, \
    get_xr_neighbors, get_xe_neighbors, get_junos_neighbors
from config_generator.generator.gentools import get_acl_list, get_unique_acl_list, \
    split_neighbors_to_group, set_evpn_groups_for_vlan, set_evpn_groups_for_xc, \
    get_evi_id_for_vlan, get_evi_id_for_xc, get_pppoe_xc_diff, get_pppoe_neighbors, \
    need_convertation_to_vlan, convert_xc_to_vlan, get_fake_scheme, \
    format_acl_name_for_se, create_remotes_config, get_esi_template, get_7600s_lo30, \
    create_ncs_hostname, get_bgp_vpnv4_neighbors, \
    create_init_config, write_bgp_vpnv4_config, write_vrf_config, write_acl_config, \
    write_aggregations_config, write_interlinks_config, write_uplink_config
from datetime import datetime
from openpyxl import load_workbook


#######################################################
def main(ssh_username, ssh_password, pe1_ip, pe2_ip, pe1_lo2, pe2_lo2, pe1_lo30, pe2_lo30,
         evi_bgp_rt_offset, se_evi_offset, se_bvi_offset, se_location, no_remotes,
         no_init, answer_yes=False):
    logger = logging.getLogger('generator.main')
    logger.info('GENERATOR STARTS')

    # Время начала выполнения:
    start_time = datetime.now()

    # Домашняя директория:
    try:
        home_directory = get_homedir_path()
    except AttributeError:
        print("Для работы скрипта требуется установить домашнюю директорию.")
        exit()

    # Проверка введенных параметров:
    print('***************************************************')
    print('**              ПРОВЕРКА ПАРАМЕТРОВ:             **')
    print('***************************************************')

    alarm = False
    ip_address_dict = {'7600-01 IP:': pe1_ip,
                       '7600-02 IP:': pe2_ip,
                       'NCS-01 Lo2:': pe1_lo2,
                       'NCS-02 Lo2:': pe2_lo2,
                       'NCS-01 Lo30:': pe1_lo30,
                       'NCS-02 Lo30:': pe2_lo30
                       }

    print()
    for key in ip_address_dict.keys():
        try:
            ipaddress.ip_address(ip_address_dict[key])
            click.echo(f'{key:15}\u001b[32m{ip_address_dict[key]}\u001b[0m')
        except ValueError:
            click.echo(f'{key:15}\u001b[31m{ip_address_dict[key]}: NOT VALID\u001b[0m')
            alarm = True

    try:
        evi_bgp_rt_offset = int(re.search(r'65050:(\d+)', evi_bgp_rt_offset).group(1))
        click.echo(f'BGP RT OFFSET: \u001b[32m{evi_bgp_rt_offset}\u001b[0m')
    except AttributeError:
        click.echo(f'BGP RT OFFSET: \u001b[31m{evi_bgp_rt_offset}: NOT VALID\u001b[0m')
        alarm = True

    if se_evi_offset <= 65534:
        click.echo(f'SE EVI OFFSET: \u001b[32m{se_evi_offset}\u001b[0m')
    else:
        click.echo(f'SE EVI OFFSET: \u001b[31m{se_evi_offset}: NOT VALID\u001b[0m')
        alarm = True

    if se_bvi_offset <= 4294967295:
        click.echo(f'SE BVI OFFSET: \u001b[32m{se_bvi_offset}\u001b[0m')
    else:
        click.echo(f'SE BVI OFFSET: \u001b[31m{se_bvi_offset}: NOT VALID\u001b[0m')
        alarm = True

    click.echo(f"SE LOCATION:   \u001b[32m{se_location}\u001b[0m")

    if alarm:
        click.echo('\n\u001b[31mВНИМАНИЕ:\u001b[0m Необходимо ввести валидные значения.')
        exit()
    elif not answer_yes and not click.confirm('\nПродолжить?', default=True):
        exit()

    # ПОДКЛЮЧЕНИЕ:
    print()
    print('***************************************************')
    print('**               ГЕНЕРАЦИЯ КОНФИГА:              **')
    print('***************************************************')

    if not ssh_username:
        ssh_username = input('\nВведите имя пользователя: ')
    if not ssh_password:
        ssh_password = getpass('Введите пароль: ')

    logger.info(f'Authentication with "{ssh_username}" username')

    while True:
        pe1_parameters = {'connection': connect(ssh_username,
                                                ssh_password,
                                                pe1_ip,
                                                check_credentials=False
                                                )
                          }
        if not pe1_parameters['connection']:
            click.echo('\u001b[31mНеверный логин\\пароль.\u001b[0m\n')
            ssh_username = input('Введите имя пользователя: ')
            ssh_password = getpass('Введите пароль: ')
        else:
            break

    pe2_parameters = {'connection': connect(ssh_username, ssh_password, pe2_ip)}
    all_pe_parameters = [pe1_parameters, pe2_parameters]  # Удалить?

    pe1_parameters['loopback2'] = pe1_lo2
    pe1_parameters['loopback30'] = pe1_lo30
    pe1_parameters['hostname'] = get_hostname(pe1_parameters['connection'])
    pe2_parameters['loopback2'] = pe2_lo2
    pe2_parameters['loopback30'] = pe2_lo30
    pe2_parameters['hostname'] = get_hostname(pe2_parameters['connection'])

    logger.info(f'PE-01 Lo2\'s ip is {pe1_parameters["loopback2"]}')
    logger.info(f'PE-01 Lo30\'s ip is {pe1_parameters["loopback30"]}')
    logger.info(f'PE-02 Lo2\'s ip is {pe2_parameters["loopback2"]}')
    logger.info(f'PE-02 Lo30\'s ip is {pe2_parameters["loopback30"]}')
    logger.info(f'The first bgp RT number is 65050:{evi_bgp_rt_offset}')
    logger.info('se_evi_offset = {}'.format(se_evi_offset))
    logger.info('se_bvi_offset = {}'.format(se_bvi_offset))
    logger.info(f'PE1\'s hostname is {pe1_parameters["hostname"]}')
    logger.info(f'PE2\'s hostname is {pe2_parameters["hostname"]}')

    #######################################################
    # ЗАГРУЗКА ДАННЫХ ИЗ ТАБЛИЦЫ

    logger.info(f'Opening excel table {pe1_parameters["hostname"][:-3]}-preparing.xlsx')

    print('Загружаем данные из таблицы...')
    while True:
        try:
            workbook_path = get_preparing_path(pe1_parameters["hostname"])
            break
        except AttributeError:
            click.echo('\u001b[31mВНИМАНИЕ:\u001b0m Файл c данными парсинга не найден.')
            print(
                f'Убедитесь, что файл существует в домашней директории '
                f'и нажмите Enter для повторной попытки')
            input()

    logger.info('Loading data from preparing table')

    workbook = load_workbook(workbook_path)
    excel_sheets = [workbook['Общий список VRF'],
                    workbook['Общий список VLAN'],
                    workbook['Общий список соседей'],
                    workbook['Список XC']
                    ]
    VRF_KEYS = ['vrf_name', 'vrf_rd', 'vrf_rt_export', 'vrf_rt_import', 'hostname']
    VLAN_KEYS = [
        'vlan_id', 'vlan_name', 'is_l2/l3', 'svi_ip', 'svi_ip_secondary',
        'svi_mac', 'svi_descr', 'svi_vrf', 'svi_acl_in', 'svi_acl_out',
        'svi_policy_in', 'svi_policy_out',
        'svi_admin_state', 'is_merged', 'neighbors', 'is_in_eigrp',
        'is_in_hsrp', 'is_in_ospf', 'alarm_neighbors', 'alarm_hsrp',
        'alarm_subnets', 'alarm_intersection', 'alarm', 'comment'
    ]
    NEIGHBOR_KEYS = [
       'neighbor', 'link_amount', 'is_l2/l3', 'hostname', "description", 'status',
       'protocol', 'ip', 'mtu', 'port_channel_interface', 'role',
       'alarm', 'comment'
    ]

    XC_KEYS = [
        'hostname', 'state', 'source_port', 'dot1q', 'remote_ip', 'pwid',
        'source_neighbor', 'source_int_description', 'alarm'
    ]
    KEYS_LIST = [VRF_KEYS, VLAN_KEYS, NEIGHBOR_KEYS, XC_KEYS]

    vrf_list, vlan_list, neighbor_list, xc_list = load_data_from_table(excel_sheets,
                                                                       KEYS_LIST)
    logger.info(f'Closing excel table {pe1_parameters["hostname"][:-3]}-preparing.xlsx')
    workbook.close()

    ################################################
    # КОНФИГ

    # Создаем общий шаблон для ethernet-segment-id
    esi_template = get_esi_template(pe1_parameters['loopback30'])

    # Сохраняем адреса соседних 7606:
    for pe_parameters in all_pe_parameters:
        lo30_ip = get_7600s_lo30(pe_parameters['connection'])
        pe_parameters['old_lo30'] = lo30_ip
        index = abs(all_pe_parameters.index(pe_parameters) - 1)
        all_pe_parameters[index]['old_neighbor_lo30'] = lo30_ip

    # Конвертируем XC, идущие с одной PE на другую, во вланы:
    for pe_parameters in all_pe_parameters:
        need_convertation_to_vlan(xc_list,
                                  pe_parameters['hostname'],
                                  pe_parameters['old_neighbor_lo30']
                                  )
    convert_xc_to_vlan(xc_list, vlan_list, pe1_parameters['hostname'])

    # Определяем EVPN_GROUP для вланов:
    set_evpn_groups_for_vlan(vlan_list)

    # Помечаем вланы, если они должны терминироваться на SE (FAKE):
    get_fake_scheme(vlan_list)

    # Парсим ACL c обеих коробок:
    acl_list = []
    for pe_parameters in all_pe_parameters:
        acl_list.extend(get_acl_list(pe_parameters['connection']))

    # Объединяем ACL с двух PE:
    acl_list = get_unique_acl_list(acl_list, vlan_list)

    # Директория для хранения сгенерированных конфигов:
    config_file_path = os.path.join(home_directory, 'config/')
    if not os.path.exists(config_file_path):
        os.makedirs(config_file_path)

    # Создаем файл с конфигурацией:
    for pe_parameters in all_pe_parameters:
        ncs_hostname = create_ncs_hostname(pe_parameters['hostname'])
        logger.info(f'Creating {pe_parameters["hostname"]}-configuration.txt file')
        print(f'Генерируем конфиг для {ncs_hostname}...')

        ncs_config_filename = f'{ncs_hostname}-configuration.txt'
        se_config_filename = f'{ncs_hostname}-SE-configuration.txt'
        ncs_config_file = open(f'{config_file_path}/{ncs_config_filename}', 'w')
        se_config_file = open(f'{config_file_path}/{se_config_filename}', 'w')

        # Общий конфиг:
        if not no_init:
            logger.info(f'Adding the baseline config for {pe_parameters["hostname"]}')
            ncs_config_file.writelines(create_init_config(ncs_hostname,
                                                          pe_parameters["loopback2"],
                                                          pe_parameters["loopback30"]
                                                          ))

        # ACL:
        logger.info(f'{pe_parameters["hostname"]} Creating ACLs config')
        write_acl_config(acl_list, pe_parameters["hostname"],
                         ncs_config_file, se_config_file)

        # iBGP соседи:
        if not no_init:
            logger.info(f'{pe_parameters["hostname"]} Generating iBGP config')
            bgp_vpnv4_neighbors = get_bgp_vpnv4_neighbors(pe_parameters['connection'])
            write_bgp_vpnv4_config(bgp_vpnv4_neighbors, ncs_config_file)

        # VRF:
        logger.info(f'{pe_parameters["hostname"]} Creating config for VRFs')
        write_vrf_config(vrf_list, ncs_config_file)

        # ФИЗИКА:
        logger.info(f'{pe_parameters["hostname"]} Splitting neighbors to '
                    f'groups (aggregation/uplink/interlink)')
        aggregation_list, uplink_list, interlink_list = split_neighbors_to_group(
            neighbor_list)

        # Выделение интерфейсы агрегациям (1-23 порт):
        logger.info(f'{pe_parameters["hostname"]} Allocating interfaces for aggregations')
        write_aggregations_config(aggregation_list, esi_template, ncs_config_file)

        # Выделение интерфейсы межкомплектам (24-25 порт):
        if not no_init:
            logger.info(f'{pe_parameters["hostname"]} Allocating interfaces for interlinks')
            write_interlinks_config(interlink_list, pe_parameters["hostname"],
                                    ncs_config_file)

        # Выделение интерфейсы межкомплектам (26-32 порт):
        logger.info(f'{pe_parameters["hostname"]} Allocating interfaces for uplinks')
        write_uplink_config(uplink_list, pe_parameters["hostname"], ncs_config_file)

        # VLANs
        # Cабики, BVI, EVPN-инстансы, BD:

        ncs_evi_list = []  # Для проверки дубликатов BVI на NCS
        se_bvi_list = []  # Использованные номера BVI на SE
        se_evi_list = []  # Использованные номера EVI на SE

        # Значения для дубликатов с конца:
        evi_bgp_rt_for_duplicates = evi_bgp_rt_offset + 4999
        se_bvi_for_duplicates = se_bvi_offset + 4999
        se_evi_for_duplicates = se_evi_offset + 4999

        logger.info('***************************************************************')
        logger.info(f'Creating subinterfaces, BVI, BD and EVPN-instances '
                    f'for {pe_parameters["hostname"]}')

        for vlan in vlan_list:

            # Получаем номер BVI/EVI. Здесь же выполняется проверка на дубликаты

            evi_id = get_evi_id_for_vlan(vlan, ncs_evi_list)

            # BVI:

            if vlan['is_l2/l3'] == 'L3':

                # Фейковая схема с терминацией на BVI на SE:

                if vlan['fake'] == 2:
                    logger.info('{} Creating BVI for vlan {} on SE'.format(
                        pe_parameters['hostname'], vlan['vlan_id'])
                    )

                    # Находим номер BVI для SE:

                    if int(vlan['vlan_id']) + se_bvi_offset not in se_bvi_list:
                        se_bvi_id = int(vlan['vlan_id']) + se_bvi_offset
                    else:
                        se_bvi_id = se_bvi_for_duplicates
                        se_bvi_for_duplicates -= 1

                    se_bvi_list.append(se_bvi_id)

                    # Конфиг:

                    se_config_file.writelines([
                        "\ninterface BVI{}\n".format(se_bvi_id),
                        "interface BVI{} description -=={}==-\n".format(se_bvi_id, vlan[
                            'svi_descr']),
                        "interface BVI{} host-routing\n".format(se_bvi_id),
                        "interface BVI{} mtu 9194\n".format(se_bvi_id),
                        "interface BVI{} ipv4 address {}\n".format(se_bvi_id,
                                                                   vlan['svi_ip']),
                        "interface BVI{} proxy-arp\n".format(se_bvi_id),
                        "interface BVI{} mac-address {}\n".format(se_bvi_id,
                                                                  vlan['svi_mac']),
                        "interface BVI{} arp timeout 250\n".format(se_bvi_id),
                        "interface BVI{} shutdown\n".format(se_bvi_id)
                    ])
                    if vlan.get('svi_vrf'):
                        se_config_file.write(
                            "interface BVI{} vrf {}\n".format(se_bvi_id, vlan['svi_vrf']))
                    if vlan.get('svi_ip_secondary'):
                        se_config_file.write(
                            "interface BVI{} ipv4 address {} secondary\n".format(
                                se_bvi_id, vlan['svi_ip_secondary']))
                    if vlan.get('svi_acl_in'):
                        se_config_file.write(
                            "interface BVI{} ipv4 access-group {} ingress\n".format(
                                se_bvi_id, format_acl_name_for_se(
                                    vlan['svi_acl_in'], pe_parameters['hostname'])))
                    if vlan.get('svi_acl_out'):
                        se_config_file.write(
                            "interface BVI{} ipv4 access-group {} egress\n".format(
                                se_bvi_id, format_acl_name_for_se(
                                    vlan['svi_acl_out'], pe_parameters['hostname'])))

                # Фейковая схема с терминацией на сабинтерфейсах SE:

                elif vlan['fake'] == 1:
                    logger.info('{} Creating L3-subinterface for vlan {} on SE'
                                ''.format(pe_parameters['hostname'], vlan['vlan_id']))

                    # Находим номер сабинтерфейса на SE:

                    if int(vlan['vlan_id']) + se_bvi_offset not in se_bvi_list:
                        se_bvi_id = int(vlan['vlan_id']) + se_bvi_offset
                    else:
                        se_bvi_id = se_bvi_for_duplicates
                        se_bvi_for_duplicates -= 1
                    se_bvi_list.append(se_bvi_id)

                    # Конфиг:

                    se_config_file.writelines([
                        "\ninterface TenGigE0/0/0/0.{}\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} description -=={}==-\n".format(
                            se_bvi_id, vlan['svi_descr']),
                        "interface TenGigE0/0/0/0.{} mtu 9194\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} ipv4 address {}\n"
                        "".format(se_bvi_id, vlan['svi_ip']),
                        "interface TenGigE0/0/0/0.{} proxy-arp\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} arp timeout 250\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} shutdown\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} encapsulation dot1q {} "
                        "second-dot1q {}\n".format(se_bvi_id,
                                                   se_bvi_offset // 1000,
                                                   vlan['vlan_id']
                                                   )
                    ])
                    if vlan.get('svi_vrf'):
                        se_config_file.write("interface TenGigE0/0/0/0.{} vrf {}\n"
                                             "".format(se_bvi_id, vlan['svi_vrf']))
                    if vlan.get('svi_ip_secondary'):
                        se_config_file.write(
                            "interface TenGigE0/0/0/0.{} ipv4 address {} secondary\n"
                            "".format(se_bvi_id, vlan['svi_ip_secondary']))
                    if vlan.get('svi_acl_in'):
                        se_config_file.write(
                            "interface TenGigE0/0/0/0.{} ipv4 access-group {} ingress\n"
                            "".format(se_bvi_id,
                                      format_acl_name_for_se(vlan['svi_acl_in'],
                                                             pe_parameters['hostname']
                                                             )
                                      ))
                    if vlan.get('svi_acl_out'):
                        se_config_file.write(
                            "interface TenGigE0/0/0/0.{} ipv4 access-group {} egress\n"
                            "".format(se_bvi_id,
                                      format_acl_name_for_se(vlan['svi_acl_out'],
                                                             pe_parameters['hostname'])
                                      ))

                # Обычная схема с терминацией на BVI на NCS:

                else:
                    logger.info(
                        '{} Creating BVI for vlan {}'.format(pe_parameters['hostname'],
                                                             vlan['vlan_id']
                                                             ))
                    ncs_config_file.writelines([
                        "\ninterface BVI{}\n".format(evi_id),
                        "interface BVI{} description -=={}==-\n".format(evi_id, vlan['svi_descr']),
                        "interface BVI{} host-routing\n".format(evi_id),
                        "interface BVI{} mtu 9194\n".format(evi_id),
                        "interface BVI{} ipv4 address {}\n".format(evi_id, vlan['svi_ip']),
                        "interface BVI{} mac-address {}\n".format(evi_id, vlan['svi_mac']),
                        "interface BVI{} arp timeout 250\n".format(evi_id)
                    ])
                    if vlan['evpn_group'] not in ['EVPN_FTTH',
                                                  'EVPN_IPTV',
                                                  'EVPN_TR69',
                                                  'EVPN_SIP_ADSL',
                                                  'EVPN_WAP',
                                                  'EVPN_MULTICAST']:
                        ncs_config_file.write(
                            "interface BVI{} proxy-arp\n".format(evi_id)
                        )
                    if vlan.get('svi_vrf'):
                        ncs_config_file.write(
                            "interface BVI{} vrf {}\n".format(evi_id, vlan['svi_vrf']))
                    if vlan.get('svi_ip_secondary'):
                        for secondary_ip in vlan['svi_ip_secondary']:
                            ncs_config_file.write(
                                "interface BVI{} ipv4 address {} secondary\n"
                                "".format(evi_id, secondary_ip))
                    if vlan.get('svi_admin_state'):
                        ncs_config_file.write("interface BVI{} shutdown\n".format(evi_id))
                    if vlan.get('svi_acl_in'):
                        ncs_config_file.write(
                            "interface BVI{} ipv4 access-group {} ingress\n"
                            "".format(evi_id, vlan['svi_acl_in']))
                    if vlan.get('svi_acl_out'):
                        ncs_config_file.write(
                            "interface BVI{} ipv4 access-group {} egress\n"
                            "".format(evi_id, vlan['svi_acl_out']))

                    # Генерируем MULTICAST, IGMP, PIM, DHCP конфиг для BVI:

                    if vlan.get('evpn_group'):
                        if vlan['evpn_group'] == 'EVPN_MULTICAST':
                            logger.info(
                                '{} Creating MULTICAST, IGMP, PIM config for BVI{}'
                                ''.format(pe_parameters['hostname'], evi_id))
                            ncs_config_file.writelines([
                                "multicast-routing address-family ipv4 interface BVI{}\n"
                                "".format(evi_id),
                                "multicast-routing address-family ipv4 interface BVI{} "
                                "enable\n".format(evi_id),
                                "router pim address-family ipv4 interface BVI{}\n"
                                "".format(evi_id),
                                "router pim address-family ipv4 interface BVI{} enable\n"
                                "".format(evi_id)
                            ])
                        if vlan['evpn_group'] in ['EVPN_FTTH',
                                                  'EVPN_IPTV',
                                                  'EVPN_TR69',
                                                  'EVPN_SIP_ADSL',
                                                  'EVPN_WAP']:
                            logger.info(
                                '{} Creating DHCP config for BVI{}'.format(
                                    pe_parameters['hostname'], evi_id))

                            ncs_config_file.write(
                                'dhcp ipv4 interface BVI{} relay profile RELAY\n'
                                ''.format(evi_id))

            # EVI:

            logger.info(
                '{} Creating EVI for vlan {} on NCS'.format(pe_parameters['hostname'],
                                                            vlan['vlan_id']
                                                            ))

            if not vlan.get('is_duplicated'):
                # RT для EVI = RT + номер влана:
                evi_bgp_rt = evi_bgp_rt_offset + int(vlan['vlan_id'])
            else:

                # Если это влан-дубликат, то высчитываем RT для EVI с конца:

                evi_bgp_rt = evi_bgp_rt_for_duplicates
                evi_bgp_rt_for_duplicates -= 1

            ncs_config_file.writelines([
                "evpn evi {} bgp \n".format(evi_id),
                "evpn evi {} bgp route-target import 65050:{}\n"
                "".format(evi_id, evi_bgp_rt),
                "evpn evi {} bgp route-target export 65050:{}\n"
                "".format(evi_id, evi_bgp_rt),
                "evpn evi {} advertise-mac\n".format(evi_id)
            ])
            logger.info(
                '{} BGP RT for EVI {} is 65050:{}'
                ''.format(pe_parameters['hostname'], evi_id, evi_bgp_rt))

            # Создаем EVI на SE:

            if vlan['fake']:

                # Находим EVI ID для SE:

                logger.info(
                    '{} Creating EVI for vlan {} on SE'
                    ''.format(pe_parameters['hostname'], vlan['vlan_id']))

                if int(vlan['vlan_id']) + se_evi_offset not in se_evi_list:
                    se_evi_id = int(vlan['vlan_id']) + se_evi_offset
                    se_evi_list.append(se_evi_id)
                else:
                    se_evi_id = se_evi_for_duplicates
                    se_evi_for_duplicates -= 1

                logger.info('{} EVI for vlan {} on SE is {}'
                            ''.format(pe_parameters['hostname'],
                                      vlan['vlan_id'],
                                      se_evi_id
                                      ))

                # Конфиг:

                se_config_file.writelines([
                    "evpn evi {} bgp \n".format(se_evi_id),
                    "evpn evi {} bgp route-target import 65050:{}\n"
                    "".format(se_evi_id, evi_bgp_rt),
                    "evpn evi {} bgp route-target export 65050:{}\n"
                    "".format(se_evi_id, evi_bgp_rt),
                    "evpn evi {} advertise-mac\n".format(se_evi_id),
                    "evpn evi {} control-word-disable\n".format(se_evi_id)
                ])

            # Сабинтерфейсы:

            # Ключ "ncs_interfaces" хранит порты NCS, куда разбанен влан
            vlan['ncs_interfaces'] = []
            for vlan_neighbor in vlan['neighbors'].split(sep=', '):

                for neighbor in neighbor_list:
                    if neighbor['neighbor'] == vlan_neighbor:

                        # Добавляем интерфейс в список интерфейсов влана.
                        # [0] - это первый интерфейс в случае порт-ченнела:
                        vlan['ncs_interfaces'].append(neighbor['ncs_interface'][0])

                        logger.info('{} Creating Bundle-Ether{}.{}'
                                    ''.format(pe_parameters['hostname'],
                                              neighbor['ncs_interface'][0],
                                              vlan['vlan_id']))

                        # Помечаем влан, если в списке соседей есть гистовый роутер:

                        if neighbor.get('is_gist_router'):
                            vlan['ncs_gist_router_port'] = neighbor['ncs_interface'][0]

                        # КОНФИГ:

                        ncs_config_file.writelines([
                            "interface Bundle-Ether{}.{} l2transport\n"
                            "".format(neighbor['ncs_interface'][0], evi_id),
                            "interface Bundle-Ether{}.{} l2transport encapsulation "
                            "dot1q {}\n".format(neighbor['ncs_interface'][0],
                                                evi_id,
                                                vlan['vlan_id']
                                                ),
                            "interface Bundle-Ether{}.{} l2transport rewrite ingress tag "
                            "pop 1 symmetric\n".format(neighbor['ncs_interface'][0],
                                                       evi_id
                                                       ),
                        ])

                        if vlan.get('is_l2/l3') == 'L3' and vlan['svi_descr']:
                            ncs_config_file.write(
                                "interface Bundle-Ether{}.{} l2transport description "
                                "-=={}==-\n".format(neighbor['ncs_interface'][0],
                                                    evi_id,
                                                    vlan['svi_descr']
                                                    ))

                        # Если влан - L2 или у SVI нет дескрипшена,
                        # то берем название сабика из имени влана:

                        else:
                            ncs_config_file.write(
                                "interface Bundle-Ether{}.{} l2transport description "
                                "-=={}==-\n".format(neighbor['ncs_interface'][0],
                                                    evi_id,
                                                    vlan['vlan_name']
                                                    ))

                        if vlan.get('svi_policy_out'):
                            ncs_config_file.write(
                                "interface Bundle-Ether{}.{} l2transport service-policy "
                                "output {}\n".format(neighbor['ncs_interface'][0],
                                                     evi_id,
                                                     vlan['svi_policy_out']
                                                     ))
                        break

            # Создаем l2-сабинтерфейсы для петли на SE:

            if vlan['fake']:

                se_config_file.writelines([
                    "interface TenGigE0/0/0/1.{} l2transport\n".format(se_bvi_id),
                    "interface TenGigE0/0/0/1.{} l2transport description -=={}==-\n"
                    "".format(se_bvi_id, vlan['svi_descr']),
                    "interface TenGigE0/0/0/1.{} l2transport encapsulation dot1q {} "
                    "second-dot1q {}\n".format(se_bvi_id, se_bvi_offset // 1000,
                                               vlan['vlan_id']),
                    "interface TenGigE0/0/0/1.{} l2transport rewrite ingress tag pop 2"
                    " symmetric\n".format(se_bvi_id),
                    "interface TenGigE0/0/0/1.{} l2transport mtu 9194\n".format(se_bvi_id)
                ])

                # Для fake с терминацией на BVI второй конец петли тоже l2:

                if vlan['fake'] == 2:
                    se_config_file.writelines([
                        "interface TenGigE0/0/0/0.{} l2transport\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} l2transport description -=={}==-\n"
                        "".format(se_bvi_id, vlan['svi_descr']),
                        "interface TenGigE0/0/0/0.{} l2transport encapsulation dot1q {} "
                        "second-dot1q {}\n".format(se_bvi_id,
                                                   se_bvi_offset // 1000,
                                                   vlan['vlan_id']
                                                   ),
                        "interface TenGigE0/0/0/0.{} l2transport rewrite ingress tag "
                        "pop 2 symmetric\n".format(se_bvi_id),
                        "interface TenGigE0/0/0/0.{} l2transport mtu 9194\n"
                        "".format(se_bvi_id)
                    ])

            # Бридж-домены:

            # Генерируем имя BD
            l2vpn_bd_name = vlan['evpn_group'].replace('EVPN_', '') + '_' + evi_id
            logger.info('{} Creating bridge-domain {}'.format(pe_parameters['hostname'],
                                                              l2vpn_bd_name
                                                              ))
            ncs_config_file.writelines([
                "l2vpn bridge group {}\n".format(vlan['evpn_group']),
                "l2vpn bridge group {} bridge-domain {}\n"
                "".format(vlan['evpn_group'], l2vpn_bd_name),
                "l2vpn bridge group {} bridge-domain {} mtu 9180\n"
                "".format(vlan['evpn_group'], l2vpn_bd_name),
                "l2vpn bridge group {} bridge-domain {} evi {}\n"
                "".format(vlan['evpn_group'], l2vpn_bd_name, evi_id)
            ])

            if vlan['is_l2/l3'] == 'L3':

                # Фейковая схема с терминацией на BVI на SE:

                if vlan['fake'] == 2:

                    node_name = re.sub(r'-NCS-PE\d+.*', '', ncs_hostname)
                    l2vpn_se_bd_name = node_name[:3] + '_' + l2vpn_bd_name

                    se_config_file.writelines([
                        "l2vpn bridge group EVPN_{} bridge-domain {}\n"
                        "".format(node_name, l2vpn_se_bd_name),
                        "l2vpn bridge group EVPN_{} bridge-domain {} mtu 9180\n"
                        "".format(node_name, l2vpn_se_bd_name),
                        "l2vpn bridge group EVPN_{} bridge-domain {} "
                        "interface TenGigE0/0/0/1.{}\n"
                        "".format(node_name, l2vpn_se_bd_name, se_bvi_id),
                        "l2vpn bridge group EVPN_{} bridge-domain {} evi {}\n"
                        "".format(node_name, l2vpn_se_bd_name, se_evi_id),
                        "l2vpn bridge group EVPN_{} bridge-domain {}_FAKE\n"
                        "".format(node_name, l2vpn_se_bd_name),
                        "l2vpn bridge group EVPN_{} bridge-domain {}_FAKE mtu 9180\n"
                        "".format(node_name, l2vpn_se_bd_name),
                        "l2vpn bridge group EVPN_{} bridge-domain {}_FAKE "
                        "interface TenGigE0/0/0/0.{}\n"
                        "".format(node_name, l2vpn_se_bd_name, se_bvi_id),
                        "l2vpn bridge group EVPN_{} bridge-domain {}_FAKE "
                        "routed interface BVI{}\n"
                        "".format(node_name, l2vpn_se_bd_name, se_bvi_id),
                    ])

                # Фейковая схема с терминацией на l3-сабинтерфейсе на SE:

                elif vlan['fake'] == 1:

                    node_name = re.sub(r'-NCS-PE\d+.*', '', ncs_hostname)
                    l2vpn_se_bd_name = node_name[:3] + '_' + l2vpn_bd_name

                    se_config_file.writelines([
                        "l2vpn bridge group EVPN_{} bridge-domain {}\n"
                        "".format(node_name, l2vpn_se_bd_name),
                        "l2vpn bridge group EVPN_{} bridge-domain {} mtu 9180\n"
                        "".format(node_name, l2vpn_se_bd_name),
                        "l2vpn bridge group EVPN_{} bridge-domain {} "
                        "interface TenGigE0/0/0/1.{}\n"
                        "".format(node_name, l2vpn_se_bd_name, se_bvi_id),
                        "l2vpn bridge group EVPN_{} bridge-domain {} evi {}\n"
                        "".format(node_name, l2vpn_se_bd_name, se_evi_id),
                    ])

                # Обычная схема с терминацией на BVI на NCS:

                else:

                    logger.info(
                        '{} Adding BVI{} to BD {}'
                        ''.format(pe_parameters['hostname'], evi_id, l2vpn_bd_name))
                    ncs_config_file.write(
                        "l2vpn bridge group {} bridge-domain {} routed interface BVI{}\n"
                        "".format(vlan['evpn_group'], l2vpn_bd_name, evi_id))

                    for vlan_ncs_interface in vlan['ncs_interfaces']:
                        logger.info('{} Adding interface Bundle-Ether{}.{} to BD {}'
                                    ''.format(pe_parameters['hostname'],
                                              vlan_ncs_interface,
                                              evi_id,
                                              l2vpn_bd_name
                                              ))

                # Добавляем сабики в BD для L3 подключений со split-horizon:

                for vlan_ncs_interface in vlan['ncs_interfaces']:
                    ncs_config_file.writelines([
                        "l2vpn bridge group {} bridge-domain {} interface Bundle-Ether"
                        "{}.{}\n".format(vlan['evpn_group'],
                                         l2vpn_bd_name,
                                         vlan_ncs_interface,
                                         evi_id
                                         ),
                        "l2vpn bridge group {} bridge-domain {} interface "
                        "Bundle-Ether{}.{} split-horizon group\n"
                        "".format(vlan['evpn_group'],
                                  l2vpn_bd_name,
                                  vlan_ncs_interface,
                                  evi_id
                                  )
                    ])

            # Добавляем сабики в BD для L2 подключений:

            else:
                for vlan_ncs_interface in vlan['ncs_interfaces']:

                    # Со split-horizon (случай с локально подключенным GIST ROUTER):

                    if vlan.get('ncs_gist_router_port'):
                        ncs_config_file.write(
                            "l2vpn bridge group {} bridge-domain {} interface "
                            "Bundle-Ether{}.{}\n".format(vlan['evpn_group'],
                                                         l2vpn_bd_name,
                                                         vlan_ncs_interface,
                                                         evi_id
                                                         ))
                        if vlan_ncs_interface != vlan.get('ncs_gist_router_port'):
                            ncs_config_file.write(
                                "l2vpn bridge group {} bridge-domain {} interface "
                                "Bundle-Ether{}.{} split-horizon group\n"
                                "".format(vlan['evpn_group'],
                                          l2vpn_bd_name,
                                          vlan_ncs_interface,
                                          evi_id
                                          ))

                    # Без split-horizon:

                    else:
                        ncs_config_file.write(
                            "l2vpn bridge group {} bridge-domain {} interface "
                            "Bundle-Ether{}.{}\n".format(vlan['evpn_group'],
                                                         l2vpn_bd_name,
                                                         vlan_ncs_interface,
                                                         evi_id
                                                         ))

            # Если влан мультикастовый, добавляем multicast-guard на сабики и в глобал:

            if vlan['evpn_group'] == 'EVPN_MULTICAST':
                ncs_config_file.writelines(
                    "l2vpn bridge group {} bridge-domain {} igmp snooping profile "
                    "multicast\n".format(vlan['evpn_group'], l2vpn_bd_name))
                for vlan_ncs_interface in vlan['ncs_interfaces']:
                    ncs_config_file.writelines(
                        "l2vpn bridge group {} bridge-domain {} interface "
                        "Bundle-Ether{}.{} igmp snooping profile multicast-guard\n"
                        "".format(vlan['evpn_group'],
                                  l2vpn_bd_name,
                                  vlan_ncs_interface,
                                  evi_id
                                  ))

        # MPLS-TE, MPLD LDP, RSVP, PIM, MULTICAST, OSPF для физических интерфейсов:

        logger.info('***************************************************************')
        logger.info('{} Creating MPLS-TE, MPLD LDP, RSVP, PIM, MULTICAST, OSPF config '
                    'for physical interfaces'.format(pe_parameters['hostname']))

        for neighbor in neighbor_list:
            if neighbor['role'] == 'uplink' or neighbor['role'] == 'interlink' and not no_init:
                # Не обрабатываем, если аплинк или межкомплект с другой PE:
                if neighbor['hostname'] != pe_parameters['hostname']:
                    continue
                for ncs_interface in neighbor['ncs_interface']:
                    ncs_config_file.writelines([
                        "rsvp interface TenGigE0/0/0/{}\n".format(ncs_interface),
                        "rsvp interface TenGigE0/0/0/{} bandwidth percentage 75\n"
                        "".format(ncs_interface),
                        "mpls traffic-eng interface TenGigE0/0/0/{}\n"
                        "".format(ncs_interface),
                        "mpls ldp interface TenGigE0/0/0/{}\n".format(ncs_interface),
                        "multicast-routing address-family ipv4 interface "
                        "TenGigE0/0/0/{}\n".format(ncs_interface),
                        "multicast-routing address-family ipv4 interface TenGigE0/0/0/{} "
                        "enable\n".format(ncs_interface),
                        "router pim address-family ipv4 interface TenGigE0/0/0/{}\n"
                        "".format(ncs_interface),
                        "router pim address-family ipv4 interface TenGigE0/0/0/{} "
                        "enable\n".format(ncs_interface),
                        "router ospf 1 area 0 interface TenGigE0/0/0/{}\n"
                        "".format(ncs_interface),
                        "router ospf 1 area 0 interface TenGigE0/0/0/{} "
                        "authentication message-digest\n".format(ncs_interface),
                        "router ospf 1 area 0 interface TenGigE0/0/0/{} "
                        "message-digest-key 1 md5 encrypted 131603171B070B243F36293821\n"
                        "".format(ncs_interface),
                        "router ospf 1 area 0 interface TenGigE0/0/0/{} network "
                        "point-to-point\n".format(ncs_interface)
                    ])

        ##################################################
        # XC

        # Генерируем EVPN_GROUP для XC:

        logger.info('***************************************************************')
        logger.info(f'{pe_parameters["hostname"]} EVPN groups generating for XCs')

        set_evpn_groups_for_xc(xc_list)

        # Существуют PPPoE XC, уходящие только с одной PE.
        # Такие XC нужно делать и на другую PE.
        # Для этого создаем список PPPoE XC, отсутствующих на текущей PE:

        pppoe_xc_diff_list = get_pppoe_xc_diff(xc_list, pe_parameters['hostname'])

        # Создаем словарь с двумя удаленными PPPoE соседями (hostname:ip):

        pppoe_neighbors = get_pppoe_neighbors(xc_list,
                                              get_hostname(all_pe_parameters[0]['connection']),
                                              get_hostname(all_pe_parameters[1]['connection'])
                                              )

        # Айпишники удаленных сторон:

        IOS_NEIGHBORS = get_ios_neighbors()
        XR_NEIGHBORS = get_xr_neighbors()
        XE_NEIGHBORS = get_xe_neighbors()
        JUNOS_NEIGHBORS = get_junos_neighbors()

        # Генерируем сабики, EVPN-инстансы, бридж-домены для XC:

        logger.info('***************************************************************')
        logger.info(f"{pe_parameters['hostname']} Creating XC config")

        for xc in xc_list:

            # Добавляем Lo2 удаленного соседа:

            if xc['remote_ip'] in IOS_NEIGHBORS.keys():
                xc['remote_lo2'] = IOS_NEIGHBORS[xc['remote_ip']]
            elif xc['remote_ip'] in XR_NEIGHBORS.keys():
                xc['remote_lo2'] = XR_NEIGHBORS[xc['remote_ip']]
            if xc['remote_ip'] in XE_NEIGHBORS.keys():
                xc['remote_lo2'] = XE_NEIGHBORS[xc['remote_ip']]
            elif xc['remote_ip'] in JUNOS_NEIGHBORS.keys():
                xc['remote_lo2'] = JUNOS_NEIGHBORS[xc['remote_ip']]

            # Не обрабатываем PPPoE XC, если они с другой PE и,
            # при этом, не содержатся в pppoe_xc_diff_list.
            # Условие может быть избыточным - проверить:

            if xc['evpn_group'] == 'EVPN_PPPoE' \
                    and xc['hostname'] != pe_parameters['hostname'] \
                    and xc['dot1q'] not in pppoe_xc_diff_list:

                logger.info('XC from {} to {} is a PPPoE-xc from another PE. Skipping'
                            ''.format(pe_parameters['hostname'],
                                      xc['source_port'],
                                      xc['remote_ip']
                                      ))
                continue

            # Генерируем EVI ID для NCS:

            evi_id = get_evi_id_for_xc(xc, ncs_evi_list)

            # Сабинтерфейсы:

            for neighbor in neighbor_list:
                if xc['source_neighbor'] == neighbor['neighbor']:
                    xc['ncs_interface'] = neighbor['ncs_interface'][0]
                    logger.info('{} Creating interface Bundle-Ether{}.{}'
                                ''.format(pe_parameters['hostname'], xc['ncs_interface'],
                                          evi_id))
                    ncs_config_file.writelines([
                        "\ninterface Bundle-Ether{}.{} l2transport\n"
                        "".format(xc['ncs_interface'], evi_id),
                        "interface Bundle-Ether{}.{} l2transport description -=={}==-\n"
                        "".format(xc['ncs_interface'],
                                  evi_id,
                                  xc['source_int_description']
                                  ),
                        "interface Bundle-Ether{}.{} l2transport encapsulation dot1q {}\n"
                        "".format(xc['ncs_interface'], evi_id, xc['dot1q']),
                        "interface Bundle-Ether{}.{} l2transport rewrite ingress "
                        "tag pop 1 symmetric\n".format(xc['ncs_interface'], evi_id)
                    ])
                    break

            # Конфиг для EVI:

            logger.info('{} Creating EVI for XC from {}'
                        ''.format(pe_parameters['hostname'], xc['source_port']))

            # BGP RT:

            if not xc.get('is_duplicated'):
                # RT для EVI = первый номер RT + номер влана
                evi_bgp_rt = evi_bgp_rt_offset + int(xc['dot1q'])

            else:
                evi_bgp_rt = evi_bgp_rt_for_duplicates
                evi_bgp_rt_for_duplicates -= 1

            logger.info('{} BGP RT for EVI{} is 65050:{}'
                        ''.format(pe_parameters['hostname'], evi_id, evi_bgp_rt))

            # EVI для SE:

            if not xc.get('not_xc'):
                logger.info(
                    '{} Creating EVI for vlan {} on SE'
                    ''.format(pe_parameters['hostname'], xc['dot1q']))

                if int(xc['dot1q']) + se_evi_offset not in se_evi_list:
                    se_evi_id = int(xc['dot1q']) + se_evi_offset
                    se_evi_list.append(se_evi_id)
                else:
                    se_evi_id = se_evi_for_duplicates
                    se_evi_for_duplicates -= 1

                logger.info(f'{pe_parameters["hostname"]} EVI for xc {xc["dot1q"]} '
                            f'on SE is {se_evi_id}')

            # Конфиг:

            ncs_config_file.writelines([
                "evpn evi {} bgp \n".format(evi_id),
                "evpn evi {} bgp route-target import 65050:{}\n"
                "".format(evi_id, evi_bgp_rt),
                "evpn evi {} bgp route-target export 65050:{}\n"
                "".format(evi_id, evi_bgp_rt),
                "evpn evi {} advertise-mac\n".format(evi_id)
            ])
            if not xc['evpn_group'] == 'EVPN_PPPoE':
                se_config_file.writelines([
                    "\nevpn evi {} bgp \n".format(se_evi_id),
                    "evpn evi {} bgp route-target import 65050:{}\n"
                    "".format(se_evi_id, evi_bgp_rt),
                    "evpn evi {} bgp route-target export 65050:{}\n"
                    "".format(se_evi_id, evi_bgp_rt),
                    "evpn evi {} advertise-mac\n".format(se_evi_id),
                    "evpn evi {} control-word-disable\n".format(se_evi_id)
                ])

            # BD:

            l2vpn_bd_name = xc['evpn_group'].replace('EVPN_', '') + '_' + evi_id
            logger.info(
                '{} Creating BD {}'.format(pe_parameters['hostname'], l2vpn_bd_name))
            logger.info("{} Adding interface Bundle-Ether{}.{} to BD {}"
                        "".format(pe_parameters['hostname'],
                                  xc['ncs_interface'],
                                  evi_id,
                                  l2vpn_bd_name)
                        )
            logger.info(
                "{} Adding EVI{} to BD {}".format(pe_parameters['hostname'], evi_id,
                                                  l2vpn_bd_name))

            ncs_config_file.writelines([
                "l2vpn bridge group {} bridge-domain {}\n"
                "".format(xc['evpn_group'], l2vpn_bd_name),
                "l2vpn bridge group {} bridge-domain {} mtu 9180\n"
                "".format(xc['evpn_group'], l2vpn_bd_name),
                "l2vpn bridge group {} bridge-domain {} interface Bundle-Ether{}.{}\n"
                "".format(xc['evpn_group'], l2vpn_bd_name, xc['ncs_interface'], evi_id),
                "l2vpn bridge group {} bridge-domain {} evi {}\n"
                "".format(xc['evpn_group'], l2vpn_bd_name, evi_id)
            ])

            # Добавляем соседей для PPPoE вланов, если влан собственный
            # или находится в pppoe_xc_diff_list:

            if xc['evpn_group'] == 'EVPN_PPPoE':
                ncs_config_file.write(
                    "l2vpn bridge group {} bridge-domain {} vfi {}\n"
                    "".format(xc['evpn_group'], l2vpn_bd_name, l2vpn_bd_name))

                for pppoe_neighbor in pppoe_neighbors.values():
                    logger.info("{} Adding neighbor {} pw-id {} to BD {}"
                                "".format(pe_parameters['hostname'],
                                          pppoe_neighbor,
                                          evi_id,
                                          l2vpn_bd_name
                                          ))
                    ncs_config_file.write(
                        "l2vpn bridge group {} bridge-domain {} vfi {} neighbor {} "
                        "pw-id {}\n".format(xc['evpn_group'],
                                            l2vpn_bd_name,
                                            l2vpn_bd_name,
                                            pppoe_neighbor, xc['pwid']
                                            ))

            # Для XC с удаленными соседями из списка p2p_neighbor_list (7600 и 903)
            # создаем XC на SE:

            elif xc['remote_ip'] in IOS_NEIGHBORS:

                node_name = re.sub(r'-NCS-PE\d+.*', '', ncs_hostname)
                l2vpn_se_bd_name = node_name[:3] + '_' + l2vpn_bd_name

                logger.info("{} Adding neighbor {} pw-id {} to BD {} on SE"
                            "".format(pe_parameters['hostname'],
                                      xc['remote_ip'],
                                      se_evi_id,
                                      l2vpn_se_bd_name
                                      ))

                se_config_file.writelines([
                    "l2vpn bridge group EVPN_{} bridge-domain {}\n"
                    "".format(node_name, l2vpn_se_bd_name),
                    "l2vpn bridge group EVPN_{} bridge-domain {} mtu 9180\n"
                    "".format(node_name, l2vpn_se_bd_name),
                    "l2vpn bridge group EVPN_{} bridge-domain {} neighbor {} pw-id {}\n"
                    "".format(node_name, l2vpn_se_bd_name, xc['remote_ip'], xc['pwid']),
                    "l2vpn bridge group EVPN_{} bridge-domain {} neighbor {} pw-id {} "
                    "split-horizon group\n".format(node_name,
                                                   l2vpn_se_bd_name,
                                                   xc['remote_ip'],
                                                   xc['pwid']
                                                   ),
                    "l2vpn bridge group EVPN_{} bridge-domain {} evi {}\n"
                    "".format(node_name, l2vpn_se_bd_name, se_evi_id)
                ])

            # Оставшиеся XC создаем на NCS:

            else:

                logger.info(
                    "{} Adding neighbor {} pw-id {} to BD {} on NCS"
                    "".format(pe_parameters['hostname'], xc['remote_ip'], evi_id,
                              l2vpn_bd_name))

                ncs_config_file.writelines([
                    "l2vpn bridge group {} bridge-domain {} neighbor {} pw-id {}\n"
                    "".format(xc['evpn_group'],
                              l2vpn_bd_name,
                              xc['remote_ip'],
                              xc['pwid']
                              ),
                    "l2vpn bridge group {} bridge-domain {} neighbor {} pw-id {} "
                    "split-horizon group\n".format(xc['evpn_group'],
                                                   l2vpn_bd_name,
                                                   xc['remote_ip'],
                                                   xc['pwid']
                                                   ),
                ])

        ##################################################

        # СТАТИКИ
        pass

        # Закрываем файлы:

        print(f'Файл {ncs_config_filename} успешно сгенерирован.')
        print(f'Файл {se_config_filename} успешно сгенерирован.\n')

        ncs_config_file.close()
        se_config_file.close()

    # Конфиг для удаленных сторон:

    if not no_remotes:

        xconnects_to_ios = []
        xconnects_to_xr = []
        xconnects_to_xe = []
        xconnects_to_junos = []

        se_loopback, se_loopback_backup = get_se_loopbacks30(se_location)
        remotes_config_filename = re.search(r"(\S+)+PE\d", all_pe_parameters[0]["hostname"]).group(1) + 'remotes-configuration.txt'

        for xc in xc_list:
            if xc['evpn_group'] != 'EVPN_PPPoE':
                if xc['remote_ip'] in IOS_NEIGHBORS.keys():
                    xconnects_to_ios.append(xc)
                elif xc['remote_ip'] in XR_NEIGHBORS.keys():
                    xconnects_to_xr.append(xc)
                elif xc['remote_ip'] in XE_NEIGHBORS.keys():
                    xconnects_to_xe.append(xc)
                elif xc['remote_ip'] in JUNOS_NEIGHBORS.keys():
                    xconnects_to_junos.append(xc)

        remotes_config_file = open(f'{config_file_path}/{remotes_config_filename}', 'w')
        parameters_for_remotes = {"ssh_username": ssh_username,
                                  "ssh_password": ssh_password,
                                  "pe1_old_lo30": all_pe_parameters[0]['old_lo30'],
                                  "pe2_old_lo30": all_pe_parameters[1]['old_lo30'],
                                  "se_loopback": se_loopback,
                                  "se_loopback_backup": se_loopback_backup,
                                  }
        print('Генерируем конфиг для удаленных соседей...')
        print('Это может занять время.')
        parameters_for_remotes['device_type'] = 'cisco_ios'
        parameters_for_remotes['xconnects'] = xconnects_to_ios
        remotes_config_file.write(create_remotes_config(**parameters_for_remotes))
        parameters_for_remotes['device_type'] = 'cisco_xr'
        parameters_for_remotes['xconnects'] = xconnects_to_xr
        remotes_config_file.write(create_remotes_config(**parameters_for_remotes))
        parameters_for_remotes['device_type'] = 'cisco_xe'
        parameters_for_remotes['xconnects'] = xconnects_to_xe
        remotes_config_file.write(create_remotes_config(**parameters_for_remotes))
        parameters_for_remotes['device_type'] = 'juniper_junos'
        parameters_for_remotes['xconnects'] = xconnects_to_junos
        remotes_config_file.write(create_remotes_config(**parameters_for_remotes))

        print(f'Файл {remotes_config_filename} успешно сгенерирован.')

    # Завершение:

    pe1_parameters['connection'].disconnect()
    pe2_parameters['connection'].disconnect()

    logger.info('***********************************************************')
    logger.info(f'End of the script. Duration time: {datetime.now() - start_time}')
    print(f'Время выполнения {datetime.now() - start_time}')


if __name__ == '__main__':
    main()
