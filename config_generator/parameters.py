import os
import json

SCRIPT_PARAMETERS_PATH = os.path.join(os.path.dirname(__file__), '.data/parameters.json')


def get_script_parameters():
    with open(SCRIPT_PARAMETERS_PATH, 'r') as f:
        parameters = json.load(f)
    return parameters


###########################################

SCRIPT_PARAMETERS = get_script_parameters()


def get_se_loopbacks30(*args):
    se_loopbacks = []
    if args:
        for location in args:
            try:
                se_loopbacks.extend(SCRIPT_PARAMETERS['se_loopbacks30'][location])
            except KeyError:
                continue
    else:
        for location in SCRIPT_PARAMETERS['se_loopbacks30'].keys():
            se_loopbacks.extend(SCRIPT_PARAMETERS['se_loopbacks30'][location])
    return se_loopbacks


def get_se_loopbacks2(*args):
    se_loopbacks = []
    if args:
        for location in args:
            try:
                se_loopbacks.extend(SCRIPT_PARAMETERS['se_loopbacks2'][location])
            except KeyError:
                continue
    else:
        for location in SCRIPT_PARAMETERS['se_loopbacks2'].keys():
            se_loopbacks.extend(SCRIPT_PARAMETERS['se_loopbacks2'][location])
    return se_loopbacks


def get_evpn_groups():
    return SCRIPT_PARAMETERS['evpn_groups']


def get_table_keys(*args):
    if args:
        table_keys = []
        for arg in args:
            table_keys.append(SCRIPT_PARAMETERS['table_keys'][arg])
        return table_keys
    return SCRIPT_PARAMETERS['table_keys']


def get_ncs_ports_ranges(*args):
    if args:
        port_ranges = []
        for arg in args:
            port_ranges.append(SCRIPT_PARAMETERS['ncs_ports_ranges'][arg])
        return port_ranges
    return SCRIPT_PARAMETERS['ncs_ports_ranges']


def get_ios_neighbors():
    return SCRIPT_PARAMETERS['xc_neighbors']['ios']


def get_xr_neighbors():
    return SCRIPT_PARAMETERS['xc_neighbors']['xr']


def get_xe_neighbors():
    return SCRIPT_PARAMETERS['xc_neighbors']['xe']


def get_junos_neighbors():
    return SCRIPT_PARAMETERS['xc_neighbors']['junos']