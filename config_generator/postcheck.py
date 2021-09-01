import json
import re
import click
import os
from config_generator.connections import connect
from config_generator.parser.parstools import get_xc_list, merge_lists, \
    add_xc_source_int_description
from config_generator.generator.gentools import set_evpn_groups_for_xc, get_7600s_lo30, \
    need_convertation_to_vlan
from config_generator.fstools import create_check_dir, get_homedir_path, get_check_path
from config_generator.connections import get_hostname, get_pe_location
from config_generator.parameters import get_se_loopbacks2, get_se_loopbacks30


def check_xc_state_before(username, password, *ip_addresses):
    check_dirpath = create_check_dir(get_homedir_path())
    check_filename = ''
    xc_list = []
    params = [{}, {}]

    for i, pe_ip in enumerate(ip_addresses):

        print('Парсим параметры XC...')
        with connect(username, password, pe_ip) as pe_connection:
            hostname = get_hostname(pe_connection)
            lo30 = get_7600s_lo30(pe_connection)
            if not check_filename:
                check_filename = get_pe_location(hostname) + '-XC'

            # Для проверки XC между старыми PE:
            params[i]['hostname'] = hostname
            params[abs(i - 1)]['neighbor_lo30'] = lo30

            xconnects = get_xc_list(pe_connection)
            add_xc_source_int_description(xconnects, pe_connection)
            set_evpn_groups_for_xc(xconnects)
            xc_list.append(xconnects)

    # Конвертация в виланы:
    for i in range(2):
        need_convertation_to_vlan(xc_list[i],
                                  params[i]['hostname'],
                                  params[i]['neighbor_lo30'])

    with open(os.path.join(check_dirpath, check_filename), 'w') as f:
        json.dump(merge_lists(xc_list), f)
    print('Готово.')


def parse_bd_name(output):
    for line in output.split('\n'):
        search = re.search(r'bridge-domain (.*?) ', line)
        if search:
            return search.group(1)
    return None


def parse_pw_state(output):
    for line in output.split('\n'):
        search = re.search(r'Neighbor.*, state: (.*)?,', line)
        if search:
            return search.group(1)
    return None


def check_xc_on_se(username, password, se_loopbacks, pe_location, xc_to_check):
    for i, se_loopback in enumerate(se_loopbacks):
        se_connection = connect(username, password,
                                se_loopback,
                                device_type='cisco_xr')
        print()
        for xc in xc_to_check:
            output = se_connection.send_command(f'show run formal l2vpn bridge group '
                                                f'EVPN_{pe_location} | i "neighbor '
                                                f'{xc["remote_ip"]} pw-id {xc["pwid"]} "')

            bd_name = parse_bd_name(output)
            if not bd_name:
                click.echo(f'SE-0{i + 1} {xc["remote_ip"]} pw-id {xc["pwid"]}: '
                           f'\u001b[31mBD для {pe_location} не найден\u001b[0m')
                continue
            output = se_connection.send_command(f'show l2vpn bridge-domain bd-name '
                                                f'{bd_name} neighbor {xc["remote_ip"]} '
                                                f'pw-id {xc["pwid"]}')
            pw_state = parse_pw_state(output)
            if pw_state == 'down':
                click.echo(f'SE-0{i + 1} {xc["remote_ip"]} pw-id '
                           f'{xc["pwid"]}: \u001b[31mDOWN\u001b[0m')
            elif pw_state == 'standby' and i == 0:  # XC на SE-01 должны быть UP
                click.echo(f'SE-0{i + 1} {xc["remote_ip"]} pw-id '
                           f'{xc["pwid"]}: \u001b[31mSTANDBY\u001b[0m')
            elif pw_state == 'up' and i == 1:  # XC на SE-02 должны быть STANDBY
                click.echo(f'SE-0{i + 1} {xc["remote_ip"]} pw-id '
                           f'{xc["pwid"]}: \u001b[31mUP\u001b[0m')
            else:
                click.echo(f'SE-0{i + 1} {xc["remote_ip"]} pw-id {xc["pwid"]}: '
                           f'{pw_state.upper()}\u001b[32m[OK]\u001b[0m')
        print()


def check_xc_on_ncs(username, password, ncs_loopbacks, xc_to_check):
    for i, ncs_loopback in enumerate(ncs_loopbacks):
        ncs_connection = connect(username, password, ncs_loopback, device_type='cisco_xr')
        print()
        for xc in xc_to_check:
            output = ncs_connection.send_command(f'show run formal l2vpn bridge group '
                                                 f'EVPN_PPPoE | i neighbor '
                                                 f'{xc["remote_ip"]} pw-id {xc["pwid"]}')
            bd_name = parse_bd_name(output)
            if not bd_name:
                click.echo(f'NCS-0{i + 1} {xc["remote_ip"]} pw-id {xc["pwid"]}: '
                           f'\u001b[31mBD не найден\u001b[0m')
                continue
            output = ncs_connection.send_command(f'show l2vpn bridge-domain bd-name '
                                                 f'{bd_name} neighbor {xc["remote_ip"]} '
                                                 f'pw-id {xc["pwid"]}')
            pw_state = parse_pw_state(output)
            if pw_state in ['down', 'standby']:
                click.echo(f'NCS-0{i + 1} {xc["remote_ip"]} pw-id '
                           f'{xc["pwid"]}: \u001b[31m{pw_state}\u001b[0m')
            else:
                click.echo(f'NCS-0{i + 1} {xc["remote_ip"]} '
                           f'pw-id {xc["pwid"]}: {pw_state} \u001b[32m[OK]\u001b[0m')
        print()


def check_xc_state_after(username, password, se_location, *ncs_ipadresses, only=None):

    se_loopbacks = get_se_loopbacks2(se_location)
    with connect(username, password, ncs_ipadresses[0]) as ncs_connection:
        pe_hostname = get_hostname(ncs_connection)
        pe_location = get_pe_location(pe_hostname)

    xconnects = get_xc_state_before(pe_hostname)
    if only != 'NCS':
        print('Проверка XC на SE...')
        xc_to_check_on_se = get_xc_to_check_on_se(xconnects)
        check_xc_on_se(username, password, se_loopbacks, pe_location, xc_to_check_on_se)
    if only != 'SE':
        print('Проверка XC на NCS...')
        xc_to_check_on_ncs = get_xc_to_check_on_ncs(xconnects)
        check_xc_on_ncs(username, password, ncs_ipadresses, xc_to_check_on_ncs)


def get_xc_state_before(hostname):
    pe_location = get_pe_location(hostname)
    with open(get_check_path(pe_location)) as f:
        xconnects = json.load(f)
    return xconnects


def get_xc_to_check_on_se(xconnects):
    xc_to_check = []
    se_loopbacks = get_se_loopbacks30()
    for xc in xconnects:
        if xc['state'] != 'DN' \
                and not xc.get('not_xc') \
                and xc['evpn_group'] != "EVPN_PPPoE" \
                and 'IPMI' not in str(xc.get('source_int_description')) \
                and xc['remote_ip'] not in se_loopbacks:
            xc_to_check.append(xc)
    return xc_to_check


def get_xc_to_check_on_ncs(xconnects):
    xc_to_check = []
    for xc in xconnects:
        if xc['evpn_group'] == "EVPN_PPPoE" and xc['state'] != "DN":
            xc_to_check.append(xc)
    return xc_to_check


def parse_xc_evi_id(output):
    for line in output.split('\n'):
        evi_id = re.search(r'^(\d+)', line)
        if evi_id:
            return evi_id.group(1)


def has_mac_from_xc(output):
    for line in output.split('\n'):
        if re.search('PW:', line):
            return True
    return False


def check_xc_mac(username, password, pe_ip, se_location, errors=False):
    """Check if there are macs from PW in evpn"""
    with connect(username, password, get_se_loopbacks2(se_location)[0],
                 device_type='cisco_xr') as se_connection:
        with connect(username, password, pe_ip) as pe_connection:
            pe_hostname = get_hostname(pe_connection)
            pe_location = get_pe_location(pe_hostname)

        xconnects = get_xc_state_before(pe_hostname)
        xc_to_check = get_xc_to_check_on_se(xconnects)

        print()
        for xc in xc_to_check:
            output = se_connection.send_command(f'show evpn evi | i {pe_location[:3]}'
                                                f'.*{xc["dot1q"]}')
            evi_id = parse_xc_evi_id(output)
            if evi_id:
                output = se_connection.send_command(f'show evpn evi vpn-id {evi_id} mac')
                if has_mac_from_xc(output):
                    if not errors:
                        click.echo(f'XC {xc["remote_ip"]} pw-id {xc["pwid"]}: маки есть')
                else:
                    click.echo(f'XC {xc["remote_ip"]} pw-id {xc["pwid"]}: '
                               f'\u001b[31mМаки не найдены\u001b[0m')
