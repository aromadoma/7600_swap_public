import logging
import click
from datetime import datetime
from config_generator.generator import generator
from config_generator.parser import parser
from config_generator.fstools import set_homedir, show_homedir, get_homedir_path, \
    create_logs_dir
from config_generator.connections import upload_config, check_configuration, enable_ssh, \
    apply_config
from config_generator.generator.gentools import create_policy
from config_generator.postcheck import check_xc_state_before, check_xc_state_after,\
    check_xc_mac


class SpecialHelpOrder(click.Group):
    def __init__(self, *args, **kwargs):
        self.list_commands = self.list_commands_for_help
        self.help_priorities = {}
        super(SpecialHelpOrder, self).__init__(*args, **kwargs)

    def get_help(self, ctx):
        return super(SpecialHelpOrder, self).get_help(ctx)

    def list_commands_for_help(self, ctx):
        """reorder the list of commands when listing the help"""
        commands = super(SpecialHelpOrder, self).list_commands(ctx)
        return (c[1] for c in sorted(
            (self.help_priorities.get(command, 1), command)
            for command in commands))

    def command(self, *args, **kwargs):
        """Behaves the same as `click.Group.command()` except capture
        a priority for listing command names in help.
        """
        help_priority = kwargs.pop('help_priority', 1)
        help_priorities = self.help_priorities

        def decorator(f):
            cmd = super(SpecialHelpOrder, self).command(*args, **kwargs)(f)
            help_priorities[cmd.name] = help_priority
            return cmd

        return decorator


@click.group(cls=SpecialHelpOrder)
def main():
    """This utility helps to migrate services from 7600 to NCS"""
    try:
        home_directory = get_homedir_path()
    except AttributeError:
        exit()
    logs_path = create_logs_dir(home_directory)
    log_file = f'{logs_path}/config-generator-log-' \
               f'{datetime.now().strftime("%d%m%y-%H%M")}.txt'
    logging.basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        level=logging.INFO, filename=log_file
    )


@main.command('parse', help_priority=0)
@click.argument('ip_addresses', nargs=2)
@click.option("-u", "ssh_username",
              type=str,
              help='Username for ssh connection')
@click.option("-p", "ssh_password", type=str, help='Password for ssh connection')
def command_parse(ssh_username, ssh_password, ip_addresses):
    """Parse cisco 7600's config"""
    pe1_ip, pe2_ip = ip_addresses
    parser.main(ssh_username, ssh_password, pe1_ip, pe2_ip)


@main.command('upload', help_priority=3)
@click.argument('ip_addresses', nargs=-1)
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
@click.option("--validate",
              type=str,
              is_flag=True,
              help='Check configuration directly on NCS')
def command_upload(username, password, validate, ip_addresses):
    """Upload config files to NCS routers"""
    upload_config(username, password, *ip_addresses, validate=validate)


@main.command('generate', help_priority=1)
@click.argument('ip_addresses', nargs=2)
@click.option("-u", "ssh_username", type=str, help='Username for ssh connection')
@click.option("-p", "ssh_password",
              type=str,
              help='Password for ssh connection')
@click.option("--pe1-lo2", "pe1_lo2",
              type=str,
              prompt='Введите Lo2 для NCS-01',
              help='NCS-01\'s loopback2')
@click.option("--pe2-lo2", "pe2_lo2",
              type=str,
              prompt='Введите Lo2 для NCS-02',
              help='NCS-02\'s loopback2')
@click.option("--pe1-lo30", "pe1_lo30",
              type=str,
              prompt='Введите Lo30 для NCS-01',
              help='NCS-01\'s loopback30')
@click.option("--pe2-lo30", "pe2_lo30",
              type=str,
              prompt='Введите Lo30 для NCS-02',
              help='NCS-02\'s loopback30')
@click.option("--rt", "evi_bgp_rt_offset",
              type=str,
              prompt='Введите первое значение BGP RT для EVI',
              help='The first BGP RT number for EVIs')
@click.option("--evi", "se_evi_offset",
              type=int,
              prompt='Введите первое значение EVI для SE',
              help='The first EVI number for SE')
@click.option("--bvi", "se_bvi_offset",
              type=int,
              prompt='Введите первое значение BVI для SE',
              help='The first BVI or l3-subinterface number for SE')
@click.option("--no-remotes", "no_remotes", is_flag=True,
              help='Don\'t create config for remote PEs')
@click.option("--no-init", "no_init", is_flag=True,
              help='Don\'t create initial part of config')
@click.option("--se", "se_location",
              type=click.Choice(['KZN', 'CHE', 'ALM', 'APS'], case_sensitive=False),
              prompt='Введите местонахождение SE',
              help='SE location')
@click.option("-y", "answer_yes", is_flag=True, help='Answer yes automatically')
def command_generate(ssh_username, ssh_password, ip_addresses, pe1_lo2, pe2_lo2,
                     pe1_lo30, pe2_lo30, evi_bgp_rt_offset, se_evi_offset,
                     se_bvi_offset, se_location, no_remotes, no_init, answer_yes=False):
    """Generate config for NCS, SE and remotes"""
    pe1_ip, pe2_ip = ip_addresses
    generator.main(ssh_username, ssh_password, pe1_ip, pe2_ip, pe1_lo2, pe2_lo2,
                   pe1_lo30, pe2_lo30, evi_bgp_rt_offset, se_evi_offset, se_bvi_offset,
                   se_location, no_remotes, no_init, answer_yes)


@main.command('validate', help_priority=4)
@click.argument('ip_addresses', nargs=-1)
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
def command_validate(username, password, ip_addresses):
    """Run validator and syntax check for uploaded config"""
    check_configuration(username, password, *ip_addresses)


@main.command('ssh-enable', help_priority=6)
@click.argument('ncs_addresses', nargs=-1)
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
def command_enable_ssh(username, password, ip_addresses):
    """Check and enable ssh2 server on NCS"""
    enable_ssh(username, password, *ip_addresses)


@main.command('apply', help_priority=5)
@click.argument('ip_addresses', nargs=-1)
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
def command_apply_config(username, password, ip_addresses):
    """Apply created configuration on NCS"""
    apply_config(username, password, *ip_addresses)


@main.group('homedir')
def command_homedir():
    """Home directory for related tables and files"""
    pass


@command_homedir.command('set')
@click.option("-p", "path",
              type=str,
              help='Path to home directory (relative or absolute)')
@click.option("--here", is_flag=True, help='Set current directory as home')
def command_homedir_set(path, here):
    """Set home directory"""
    set_homedir(path, here)


@command_homedir.command('show')
def command_homedir_show():
    """Show current home directory if exists"""
    show_homedir()


@main.command('policy-create', help_priority=7)
@click.argument('policies', nargs=-1)
def command_policy_create(policies):
    """Create policy configuration"""
    for policy in policies:
        print(create_policy(policy))


@main.group('check')
def command_check():
    """Check connections before and after swap"""
    pass


@command_check.group('xc')
def command_check_xc():
    """Check XC states before and after swap"""
    pass


@command_check_xc.command('state-before')
@click.argument('old_pe_addresses', nargs=2)
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
def command_check_xc_before(username, password, old_pe_addresses):
    """Get XC states before swap to compare later"""
    check_xc_state_before(username, password, *old_pe_addresses)


@command_check_xc.command('state-after')
@click.argument('ncs_addresses', nargs=2)
@click.argument('se_location')
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
@click.option("--only",
              type=click.Choice(['SE', 'NCS'], case_sensitive=False),
              help='Check xc only on SE or NCS')
def command_xc_check_after(username, password, se_location, only, ncs_addresses):
    """Get XC states after swap"""
    check_xc_state_after(username, password, se_location, *ncs_addresses, only=only)


@command_check_xc.command('mac')
@click.argument('old_pe_address')
@click.argument('se_location')
@click.option("-u", "username",
              type=str,
              prompt='Введите имя пользователя',
              help='Username for ssh connection')
@click.option("-p", "password",
              type=str,
              prompt='Введите пароль',
              hide_input=True,
              help='Password for ssh connection')
@click.option("--errors",
              is_flag=True,
              help='Show only BDs without mac from PW')
def command_check_xc_mac(username, password, old_pe_address, se_location, errors):
    """Check if there are mac addresses from pseudowire in EVPN"""
    check_xc_mac(username, password, old_pe_address, se_location, errors)


if __name__ == '__main__':
    main()
