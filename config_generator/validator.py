import re
import click
# from config_generator.generator.gentools import create_policy
# from config_generator.connections import connect, get_hostname, check_ping


def format_syntax_error(string):
    message = re.search('^%(.*)', string).group(1)
    return f'\u001b[31m{message}\u001b[0m'


def get_pointer_position(string):
    return string.index('^')


def parse_syntax_errors(output):
    strings = output.split('\n')[9:]  # Срезаем заголовок
    for i, string in enumerate(strings):
        if re.search(r'^%', string):
            strings[i] = format_syntax_error(string)
    return strings


def format_validator_error(output):
    message = re.search('^!!%(.*?):', output).group(1)
    if 'WARNING' in message:
        return re.sub(message, f'\u001b[33m{message}:\u001b[0m', output)
    return re.sub(message, f'\u001b[31m{message}:\u001b[0m', output)


def is_validation_failed(output):
    return re.search('failed during validate commit', output)


def parse_validator_errors(output):
    if is_validation_failed(output):
        errors = []
        message = ''
        for string in output.split('\n')[9:]:  # Срезаем заголовок
            if re.search('^!!%.*?:', string):
                if not re.search('interfaces in preconfigured state', string):
                    message += format_validator_error(string)
                    message += '\n'
                    errors.append(message)
                message = ''
            else:
                message += string
                message += '\n'
    else:
        return None
    return errors


def has_syntax_errors(output):
    return re.search('errors in one or more', output)


def is_validator_enabled(connection):
    output = connection.send_command('sh run | i validation')
    return True if re.search('configuration validation enable', output) else False


def enable_validator(connection):
    connection.send_config_set('configuration validation enable')
    connection.commit()


def start_validator_check(connection):
    validator_output = connection.send_command('validate commit show-error')
    validator_errors = parse_validator_errors(validator_output)
    return validator_errors


def load_config(connection, config_filename):
    connection.config_mode()
    click.echo('Загружаем конфигурацию из файла...')
    load_output = connection.send_command(f'load harddisk:{config_filename}',
                                          expect_string=r'RP\/\d\/RP\d\/CPU\d:.*#',
                                          max_loops=1000,
                                          strip_prompt=True)
    return 1 if has_syntax_errors(load_output) else 0


def is_config_uploaded(connection, config_filename):
    output = connection.send_command('dir harddisk:')
    return True if re.search(config_filename, output) else False


def get_missing_policies(errors):
    missing_policies = []
    for error in errors:
        try:
            policy = re.search('Service policy name "(.*)" '
                               'does not exist', error).group(1)
            missing_policies.append(policy)
        except AttributeError:
            continue
    return missing_policies


# def create_missing_policies(missing_policies):
#     policies_config = ''
#     for policy in missing_policies:
#         policies_config += create_policy(policy)
#     return policies_config


def start_syntax_check(connection):
    syntax_output = connection.send_command('show configuration failed load detail')
    syntax_errors = parse_syntax_errors(syntax_output)
    return syntax_errors


def validate_config(connection, config_filename):
    if not is_config_uploaded(connection, config_filename):
        print(f'Файл конфигурации не найден на NCS.')
        return 1
    if not is_validator_enabled(connection):
        click.echo('Включаем валидатор на NCS...')
        enable_validator(connection)
    else:
        click.echo('Валидатор на NCS включен.')
    if load_config(connection, config_filename):  # load_config выдал ошибку синтаксиса
        syntax_errors = start_syntax_check(connection)
    else:
        syntax_errors = None
    validator_errors = start_validator_check(connection)
    connection.send_command('abort', expect_string=r'RP/\d/RP\d/CPU\d:.*#')

    click.echo('\n**************************************************************')
    click.echo('                       ПРОВЕРКА КОНФИГА                         ')
    click.echo('**************************************************************\n')
    click.echo(f'\u001b[33m{"ВАЛИДАТОР:":^62}\u001b[0m\n')
    if validator_errors:
        for error in validator_errors:
            click.echo(error)
        click.echo()
    else:
        click.echo(f'{"Проблем не обнаружено.":^62}\n')
    click.echo(f'\u001b[33m{"СИНТАКСИС:":^62}\u001b[0m\n')
    if syntax_errors:
        for line in syntax_errors:
            click.echo(line)
    else:
        click.echo(f'{"Проблем не обнаружено.":^62}\n')

    # # НАДО СРАЗУ ИХ ГЕНЕРИРОВАТЬ И НЕ ВКЛЮЧАТЬ В INIT CONFIG:
    # missing_policies = get_missing_policies(validator_errors)
    # if missing_policies:
    #     print('Найдены отсутствующие политики:', *missing_policies)
    #     if click.confirm('Cоздать? Политики будут добавлены сразу на NCS'):
    #         print(create_missing_policies(missing_policies))

