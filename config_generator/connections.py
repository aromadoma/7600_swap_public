import re
from netmiko import ConnectHandler, file_transfer
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException
import click
from getpass import getpass
from config_generator.fstools import get_config_path
from config_generator.validator import validate_config, is_config_uploaded, load_config
import logging
import sys
from subprocess import check_output, CalledProcessError


def connect(username, password, ip,
            device_type='cisco_ios',
            check_credentials=True,
            show_status=True):
    while True:
        connection_settings = {
            'device_type': device_type,
            'ip': ip,
            'username': username,
            'password': password,
        }
        # Проблема с подключением к XR по telnet:
        if connection_settings['device_type'] == 'cisco_xr_telnet':
            connection_settings['global_delay_factor'] = 1.5
            connection_settings['fast_cli'] = False

        try:
            if show_status:
                click.echo(f'Подключение к [{ip}]...')
            connection = ConnectHandler(**connection_settings)
            hostname = get_hostname(connection)
            if show_status:
                click.echo(f'\u001b[32m{hostname} [OK].\u001b[0m')
            return connection
        except NetMikoAuthenticationException:
            if not check_credentials:  # Чтобы изменить юзер/пасс в глобале
                return None
            click.echo('\u001b[31mНеверный логин\\пароль.\u001b[0m\n')
            username = input('Введите имя пользователя: ')
            password = getpass('Введите пароль: ')
        except NetMikoTimeoutException:
            click.echo(f'\u001b[31m{ip}: Устройство недоступно.\u001b[0m\n')
            ip = input('Проверьте IP и введите заново: ')


def get_hostname(connection):
    """Get hostname from device for which the ssh-connection is established"""
    hostname = connection.find_prompt().replace('#', '')
    hostname = re.sub(r'RP/\d/RP\d/CPU\d:', '', hostname)  # if IOS-XR
    return hostname


def get_pe_location(hostname):
    return re.search(r'(?:RP/\d/RP\d/CPU\d:)?(.*?-.*?)-', hostname).group(1)


def get_pe_location_from_hostname(hostname):
    return re.search(r'(?:RP/\d/RP\d/CPU\d:)?(.*?-.*?)-', hostname).group(1)


def connect_to_devices(username, password, *args, device_type='cisco_ios'):
    connections = []
    for ip in args:
        connections.append(connect(username, password, ip, device_type=device_type))
    return connections


def upload_config(username, password, *args, validate=False):
    for ip in args:
        connection = connect(username, password, ip, device_type='cisco_xr')
        hostname = get_hostname(connection)
        config_filename = f'{hostname}-configuration.txt'
        try:
            config_path = get_config_path(hostname)
        except AttributeError:
            click.echo(f'\u001b[31mФайл конфигурации для {hostname} не найден.\u001b[0m')
            return 1
        transfer_dict = file_transfer(connection,
                                      source_file=config_path,
                                      dest_file=config_filename,
                                      file_system=f'/misc/disk1/',
                                      direction='put',
                                      overwrite_file=True)
        if transfer_dict['file_verified']:
            if transfer_dict['file_transferred']:
                click.echo(f'\u001b[32mФайл конфигурации для {hostname} загружен.'
                           f'\u001b[0m')
                click.echo(f'harddisk:{hostname}-configuration.txt\n')
            else:
                click.echo(f'\u001b[32mФайл конфигурации для {hostname} уже существует, '
                           f'MD5 совпадают.\u001b[0m')
        if validate:
            validate_config(connection, config_filename)

        connection.disconnect()


def check_configuration(username, password, *args):
    for ip in args:
        connection = connect(username, password, ip, device_type='cisco_xr')
        hostname = get_hostname(connection)
        config_filename = f'{hostname}-configuration.txt'
        validate_config(connection, config_filename)
        connection.disconnect()


def is_ssh_configured(telnet_connection):
    output = telnet_connection.send_command('sh run formal | i ssh')
    if not re.search('ssh server v2', output) \
            or not re.search('ssh server vrf MGMT', output):
        return False
    else:
        return True


# def generate_rsa_key(telnet_connection, key_length):
#     logger = logging.getLogger("generate_rsa_key")
#     print('start generate_rsa_key')
#     output = telnet_connection.send_command('crypto key generate rsa')
#     print(output)
#     if 'Do you really want to replace them?' in output:
#         output = telnet_connection.send_command('yes')
#         print(output)
#     if 'How many bits in the modulus' in output:
#         print(f'sending {key_length}')
#         output = telnet_connection.send_command(key_length)
#         print(output)


def configure_ssh(telnet_connection):
    telnet_connection.send_config_set(['ssh server v2', 'ssh server vrf MGMT'])
    telnet_connection.commit()
    telnet_connection.exit_config_mode()


def enable_ssh(username, password, *args, key_length='1024'):
    for ip in args:
        telnet_connection = connect(username, password, ip,
                                    device_type='cisco_xr_telnet')
        hostname = get_hostname(telnet_connection)

        if not is_ssh_configured(telnet_connection):
            if click.confirm(f'SSH на {hostname} не настроен, или настроен неверно '
                             f'(VRF не MGMT).\nВключить?', default=True):
                print('Добавляем конфиг для ssh...')
                configure_ssh(telnet_connection)
                # print('Генерируем ключ...')
                # generate_rsa_key(telnet_connection, key_length)
                print('Готово.')
        else:
            print(f'SSH на {hostname} уже настроен.')
        telnet_connection.disconnect()


def check_ping(host):
    if 'linux' in sys.device_type:
        key = 'c'
    else:
        key = 'n'
    try:
        check_output(f'ping -{key} 10 -i ,5 {host} -q', shell=True)
        print('check_ping: ПИНГУЕТСЯ')
    except CalledProcessError:
        print('check_ping: НЕ ПИНГУЕТСЯ')
        return False
    return True


def apply_config(username, password, *args):
    for ip in args:
        connection = connect(username, password, ip, device_type='cisco_xr')
        hostname = get_hostname(connection)
        config_filename = f'{hostname}-configuration.txt'
        if is_config_uploaded(connection, config_filename):
            if load_config(connection, config_filename):
                click.echo('\u001b[31mВНИМАНИЕ:\u001b[0m Обнаружены ошибки синтаксиса. '
                           'Проверьте конфиг.')
            else:
                connection.commit(confirm=True, confirm_delay=60)
                if check_ping(ip):
                    print('ПИНГУЕТСЯ - КОММИТИМ')
                    connection.commit()
            connection.disconnect()
        else:
            print(f'\u001b[31mФайл конфигурации не найден на NCS.\u001b[0m')