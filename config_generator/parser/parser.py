from getpass import getpass
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from config_generator.excel_manager import create_preparation_table
from config_generator.connections import get_hostname, connect
from config_generator.parser.parstools import *

####################################################
# ЛОГГЕР
####################################################

logger = logging.getLogger(f'PARSER')
logger.info(f'START')

####################################################
# ТЕЛО СКРИПТА
####################################################


def main(ssh_username, ssh_password, pe1_ip, pe2_ip):

    start_time = datetime.now()

    print('\n***************************************************')
    print('**                ПАРСИНГ КОНФИГА                **')
    print('***************************************************')
    if not ssh_username:
        ssh_username = input('\nВведите имя пользователя: ')
    if not ssh_password:
        ssh_password = getpass('Введите пароль: ')
    logging.info(f'Authentication with "{ssh_username}" username')

    # Проверка введенных IP:
    if not pe1_ip:
        pe1_ip = input('Введите ip-адрес PE-01: ')
    logging.info(f'PE-01\'s ip address: {pe1_ip}')
    if not pe2_ip:
        pe2_ip = input('Введите ip-адрес PE-02: ')
    logging.info(f'PE-02\'s ip address: {pe2_ip}')
    while True:
        if pe2_ip == pe1_ip:
            click.echo('\u001b[31mАдрес PE-02 совпадает с PE-01.\u001b[0m\n')
            logging.info('Entered address is the same as PE1')
            pe1_ip = input('Введите ip-адрес PE-01: ')
            pe2_ip = input('Введите ip-адрес PE-02: ')
        else:
            break

    # Подключение:
    while True:
        pe1_connection = connect(ssh_username,
                                 ssh_password,
                                 pe1_ip,
                                 check_credentials=False)
        if not pe1_connection:
            click.echo('\u001b[31mНеверный логин\\пароль.\u001b[0m\n')
            ssh_username = input('Введите имя пользователя: ')
            ssh_password = getpass('Введите пароль: ')
        else:
            break
    pe2_connection = connect(ssh_username, ssh_password, pe2_ip)
    pe1_hostname = get_hostname(pe1_connection)
    pe2_hostname = get_hostname(pe2_connection)
    pe_hostnames = [pe1_hostname, pe2_hostname]
    pe_connections = [pe1_connection, pe2_connection]

    #######################################################
    # СБОР ИНФОРМАЦИИ
    ##########################################################

    # Собираем вланы:
    print()
    print("Генерируется список вланов...")
    logging.info('CREATING VLAN LISTS')
    vlan_lists_from_pes = []  # Список словарей с информацией о вланах
    with ThreadPoolExecutor(max_workers=2) as executor:
        for result in executor.map(get_vlan_list, pe_hostnames, pe_connections):
            vlan_lists_from_pes.append(result)

    # Проверяем если ли влан в биллинге:
    print('Проверяем наличие вланов в биллинге...')
    logging.info('CHECKING VLAN PRESENCE IN BILLING')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(set_billing_flag, vlan_lists_from_pes, pe_hostnames)

    # Проверяем есть ли маки во вланах, которых нет в биллинге:
    print('Проверяем наличие маков во вланах...')
    logging.info('{} CHECKING MAC-ADDRESSES PRESENCE IN VLAN')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(set_mac_flag, vlan_lists_from_pes, pe_hostnames, pe_connections)

    # Проверяем есть ли last input и существует ли L3 интерфейс.
    print('Проверяем наличие last input...')
    logging.info('CHECKING LAST INPUT')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(check_uptime, pe_hostnames, pe_connections)  # Проверяем аптайм
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(set_last_input_flag, vlan_lists_from_pes,
                     pe_hostnames, pe_connections)

    # Вердикт, переносим влан или нет:
    logging.info('CHECKING IS_TRANSFERABLE FLAG')
    for vlan_list, hostname in zip(vlan_lists_from_pes, pe_hostnames):
        set_transferable_flag(vlan_list, hostname)

    # Для SVI тянем параметры:
    print('Проверяем параметры SVI...')
    logging.info('CHECKING SVI PARAMETERS')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(get_svi_config, vlan_lists_from_pes, pe_hostnames, pe_connections)

    # Для SVI проверяем EIGRP:
    print('Проверяем интерфейсы c EIGRP...')
    logging.info('CHECKING EIGRP INTERFACES')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(set_eigrp_flag, vlan_lists_from_pes, pe_hostnames, pe_connections)

    # Для SVI проверяем HSRP:
    print('Проверяем интерфейсы с HSRP...')
    logging.info('CHECKING HSRP INTERFACES')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(set_hsrp_flag, vlan_lists_from_pes, pe_hostnames, pe_connections)

    print('Достаем mac-адреса для SVI...')
    logging.info('{} CHECKING SVIs\' MAC-ADDRESSES')
    for vlan_list, hostname, connection in zip(vlan_lists_from_pes,
                                               pe_hostnames, pe_connections):
        set_svi_mac(vlan_list, hostname, connection)

    # Для SVI проверяем OSPF:
    print('Проверяем интерфейсы c OSPF...')
    logging.info('CHECKING OSPF INTERFACES')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(set_ospf_flag, vlan_lists_from_pes, pe_hostnames, pe_connections)

    # Форматируем полученные параметры SVI, обрабатываем исключения:
    logging.info('FORMATTING SVI PARAMETERS')
    for vlans in vlan_lists_from_pes:
        format_vlan_config(vlans)

    # Генерируется список физических интерфейсов:
    print('Генерируем список физических интерфейсов...')
    logging.info('GATHERING PHYSICAL INTERFACES\' PARAMETERS')
    physical_interface_list = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        for result in executor.map(get_physint_list, pe_hostnames, pe_connections):
            physical_interface_list.append(result)

    # Отмечаем порт-ченнелы и их членов:
    print('Отмечаем порт-ченнелы...')
    logging.info('MARKING PORT-CHANNELS AND THEIR MEMBERS')
    for interfaces in physical_interface_list:
        set_portchannel_flag(interfaces)
    for connection, interfaces in zip(pe_connections, physical_interface_list):
        mark_portchannel_members(connection, interfaces)

    # Тянем параметры физ интерфейсов:
    print('Проверяем L2/L3 для физических интерфейсов...')
    logging.info('CHECKING L2/L3 FOR PHYSICAL INTERFACES')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(add_physint_level, physical_interface_list,
                     pe_hostnames, pe_connections)

    print('Проверяем MTU...')
    logging.info('CHECKING MTU FOR PHYSICAL INTERFACES')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(add_physint_mtu, physical_interface_list,
                     pe_hostnames, pe_connections)

    # Тянем CDP соседей с физических интерфейсов:
    print('Ищем CDP соседей...')
    logging.info('SEARCHING FOR NEIGHBORS ON PHYSICAL INTERFACES')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(add_neighbors, physical_interface_list,
                     pe_hostnames, pe_connections)

    # Определяем роль линка в топологии:
    print('Определяем роли линков в топологии...')
    logging.info('DETERMINING LINK ROLE IN TOPOLOGY')
    for interfaces in physical_interface_list:
        add_physint_role(interfaces)

    # Составляем список соседей для каждого влана
    print('Составляем список соседей для каждого влана...')
    logging.info('CREATING NEIGHBORS LIST FOR EACH VLAN')
    for vlans, phys_interfaces in zip(vlan_lists_from_pes, physical_interface_list):
        add_neighbors_to_vlans(vlans, phys_interfaces)

    # Создаем список VRF и их параметров:
    print('Парсим параметры VRF...')
    logging.info('CHECKING VRF')
    vrf_lists_from_pes = []  # Список, содержащий словари с параметрами VRF
    with ThreadPoolExecutor(max_workers=2) as executor:
        for result in executor.map(get_vrf_parameters, vlan_lists_from_pes,
                                   pe_hostnames, pe_connections):
            vrf_lists_from_pes.append(result)

    # Тянем список XC:
    print("Генерируется список XC...")
    logging.info('CREATING XC LIST')
    xc_lists_from_pes = []  # Список словарей, содержащих данные об XC
    with ThreadPoolExecutor(max_workers=2) as executor:
        for result in executor.map(get_xc_list, pe_connections):
            xc_lists_from_pes.append(result)

    # Соотносим сабики для XC с агрегацией:
    logging.info('GETTING SOURCE NEIGHBOR FOR XC')
    for xc_list, phys_interfaces in zip(xc_lists_from_pes, physical_interface_list):
        add_xc_source_neighbors(xc_list, phys_interfaces)

    # Тянем дескрипшены для сабинтерфейсов с XC:
    logging.info('GETTING DESCRIPTIONS FOR SOURCE INTERFACES FOR XC')
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(add_xc_source_int_description, xc_lists_from_pes, pe_connections)

    pe1_connection.disconnect()
    pe2_connection.disconnect()

    ############################################################
    # ОБЪЕДИНЕНИЕ СПИСКОВ С ДВУХ КОРОБОК
    ############################################################

    # Создаем список уникальных VLAN:
    print('Создается общий список VLAN...')
    logging.info('CREATING AGGREGATED VLAN LIST')
    vlans = merge_lists(vlan_lists_from_pes)
    unique_vlan_list = format_unique_vlan_config(get_unique_vlans(vlans))

    # Создаем список уникальных физических интерфейсов:
    print('Создается список уникальных соседей...')
    logging.info('CREATING AGGREGATED NEIGHBOR (INTERFACE) LIST')
    phys_interfaces = merge_lists(physical_interface_list)
    unique_neighbor_list = get_unique_neighbors(phys_interfaces)

    # Создаем список уникальных VRF:
    print('Cоздается список уникальных VRF...')
    logging.info('CREATING AGGREGATED VRF LIST')
    vrf_list = merge_lists(vrf_lists_from_pes)
    unique_vrf_list = get_unique_vrf_list(vrf_list)

    ##########################################################
    # ЗАПИСЬ В EXCEL:
    ##########################################################

    workbook_name = pe1_hostname[:-3] + '-preparing.xlsx'
    logging.info(f'CREATING EXCEL TABLE {workbook_name}')

    VLAN_KEYS = [
        'hostname', 'vlan_id', 'vlan_name', 'vlan_interfaces', 'is_in_billing', 'has_mac',
        'hasnt_last_input', 'is_l2/l3', 'svi_ip', 'svi_ip_secondary', 'svi_descr',
        'svi_vrf', 'svi_acl_in', 'svi_acl_out', 'svi_policy_in', 'svi_policy_out',
        'svi_admin_state', 'is_transferable', 'neighbors', 'is_in_eigrp', 'is_in_hsrp',
        'is_in_ospf', 'alarm_neighbors', 'alarm_hsrp', 'alarm_subnets',
        'alarm_intersection', 'alarm', 'comment']
    VRF_KEYS = ['hostname', 'vrf_name', 'vrf_rd', 'vrf_rt_export', 'vrf_rt_import']
    XC_KEYS = [
        'hostname', 'state', 'source_port', 'dot1q', 'remote_ip', 'pwid',
        'source_neighbor', 'source_int_description', 'alarm', 'comment']
    PHYS_INT_KEYS = [
        'hostname', 'name', 'status', 'protocol', 'description', 'is_l2/l3', 'role', 'ip',
        'mtu', 'neighbor', 'port_channel_member', 'port_channel_interface', 'alarm',
        'comment']
    UNIQUE_VRF_KEYS = ['vrf_name', 'vrf_rd', 'vrf_rt_export', 'vrf_rt_import', 'hostname']
    UNIQUE_VLAN_KEYS = [
        'vlan_id', 'vlan_name', 'is_l2/l3', 'svi_ip', 'svi_ip_secondary', "svi_mac",
        'svi_descr', 'svi_vrf', 'svi_acl_in', 'svi_acl_out', 'svi_policy_in',
        'svi_policy_out', 'svi_admin_state', 'is_merged', 'neighbors', 'is_in_eigrp',
        'is_in_hsrp', 'is_in_ospf', 'alarm_neighbors', 'alarm_hsrp', 'alarm_subnets',
        'alarm_intersection', 'alarm', 'comment']
    NEIGHBOR_KEYS = [
       'neighbor', 'link_amount', 'is_l2/l3', 'hostname', "description", 'status',
       'protocol', 'ip', 'mtu', 'port_channel_interface', 'role',
       'alarm', 'comment']

    create_preparation_table(workbook_name,
                             vlan_keys=VLAN_KEYS,
                             vlan_data=merge_lists(vlan_lists_from_pes),
                             vrf_keys=VRF_KEYS,
                             vrf_data=merge_lists(vrf_lists_from_pes),
                             phys_int_keys=PHYS_INT_KEYS,
                             phys_int_data=phys_interfaces,
                             xc_keys=XC_KEYS,
                             xc_data=merge_lists(xc_lists_from_pes),
                             unique_vrf_keys=UNIQUE_VRF_KEYS,
                             unique_vrf_data=unique_vrf_list,
                             unique_vlan_keys=UNIQUE_VLAN_KEYS,
                             unique_vlan_data=unique_vlan_list,
                             neighbor_keys=NEIGHBOR_KEYS,
                             neighbor_data=unique_neighbor_list
                             )

    # Завершение:
    logging.info(f'End of the script. Duration time: {datetime.now() - start_time}')
    print(f'Время выполнения {datetime.now() - start_time}')


if __name__ == '__main__':
    main()
