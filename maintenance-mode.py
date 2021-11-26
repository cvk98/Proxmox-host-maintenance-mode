import sys
import requests
import urllib3
from time import sleep
from copy import deepcopy

server = "https://10.10.10.100:8006"
auth = {'username': "root@pam", 'password': "YOUR_PASSWORD"}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

THRESHOLD = 0.9  # Опасное пороговое значение нагрузки / Dangerous loading threshold
RISK = 1.1  # 10% на увеличение загрузки хостов во время миграции / 10% to increase the load of hosts during migration

payload = dict()
header = dict()


class Cluster:
    def __init__(self, server: str, data: dict):
        self.server: str = server
        self._data: dict = data
        self.free_mem: int = 0
        self.free_cpu: float = 0
        self.vms: dict = {}
        self.lxcs: dict = {}
        self.__authorization()
        self.__resources_calculation()
        self.cluster_vms()
        self.hosts: list = self.cluster_hosts()
        self.show()

    def __authorization(self):
        """Авторизация и получение токена и тикета.
           Authorization and receipt of a token and ticket."""
        global payload, header
        url = f'{self.server}/api2/json/access/ticket'
        print(f'Попытка авторизации...')
        get_token = requests.post(url, data=self._data, verify=False)
        if get_token.ok:
            print(f'Успешная авторизация. Код ответа: {get_token.status_code}')
        else:
            print(f'Ошибка авторизации. Код ответа: {get_token.status_code} ({get_token.reason})')
            sys.exit()
        payload = {'PVEAuthCookie': (get_token.json()['data']['ticket'])}
        header = {'CSRFPreventionToken': (get_token.json()['data']['CSRFPreventionToken'])}

    def __resources_calculation(self):
        """Вычисляем ресурсы кластера. / Calculating cluster resources."""
        self.max_mem: int = 0
        self.mem: int = 0
        self.maxcpu: int = 0
        self.cpu_load: float = 0  # от 0 до 1
        cluster_dict: dict = {}
        url = f'{self.server}/api2/json/cluster/resources'
        print(f'Попытка получения информации о кластере...')
        resources_request = requests.get(url, cookies=payload, verify=False)
        if resources_request.ok:
            print(f'Информация о кластере получена. Код ответа: {resources_request.status_code}')
        else:
            print(f'Не удалось получить информацию о кластере. Код ответа: {resources_request.status_code} /'
                  f'({resources_request.reason})')
            sys.exit()
        self.cluster_information = (resources_request.json()['data'])
        del resources_request
        count = 0
        cpu_load_temp = 0
        for _ in self.cluster_information:
            if _["status"] == "online":
                count += 1
                self.max_mem += int(_["maxmem"])  # Всего ОЗУ в кластере
                self.mem += int(_["mem"])  # Используется ОЗУ в кластере
                self.maxcpu += int(_["maxcpu"])  # Всего ЦПУ в кластере
                cpu_load_temp += float(_["cpu"])
                cluster_dict[_["node"]] = int(_["maxmem"]), int(_["mem"]), int(_["maxcpu"]), float(_["cpu"])
        self.cluster_dict = dict(sorted(cluster_dict.items(), key=lambda host: host[0]))
        self.mem_load: float = self.mem / self.max_mem  # Загрузка памяти кластера
        self.cpu_load: float = cpu_load_temp / count  # Загрузка процессоров кластер
        if THRESHOLD <= self.mem_load < 1:
            print(f'Слишком высокая загрузка процессоров кластера')
            print(f'Миграция невозможна. Срочно примите мары!')
            sys.exit()
        elif self.mem_load > 1:
            print(f"+++Загрузка памяти кластера не может быть больше 1, а тут {self.mem_load}!+++")
            raise ValueError
        if self.cpu_load > 1:
            print(f"+++Загрузка CPU кластера не может быть больше 1, а тут {self.cpu_load}!+++")
            raise ValueError
        self.free_mem = self.max_mem - self.mem
        self.free_cpu = (THRESHOLD - self.cpu_load) * self.maxcpu

    def cluster_vms(self):
        """Определяем запущенные виртуальные машины/контейнеры в кластере.
           Defining running virtual machines/containers in the cluster."""
        for _ in self.cluster_information:
            if _["type"] == "qemu" and _["status"] == "running":
                self.vms[_["vmid"]] = _["name"], _["maxmem"], _["mem"], _["maxcpu"], _["cpu"], _["node"]
            elif _["type"] == "lxc" and _["status"] == "running":
                self.vms[_["vmid"]] = _["name"], _["maxmem"], _["mem"], _["maxcpu"], _["cpu"], _["node"]
                self.lxcs[_["vmid"]] = _["name"], _["maxmem"], _["mem"], _["maxcpu"], _["cpu"], _["node"]
        if not self.vms and not self.lxcs:
            print(f'Нет виртуальных машин/контейнеров или ошибка в методе Cluster.cluster_vms')
            sys.exit()

    def cluster_hosts(self):
        """Создаём хосты подставляя данные из кластера.
           Creating hosts by substituting data from the cluster."""
        hosts: list = []
        for host, item in self.cluster_dict.items():
            host = Host(item[0], item[1], item[2], item[3], str(host), self)
            hosts.append(host)
        return hosts

    def show(self):
        print()
        print(" Информация о кластере ".center(50, "-"))
        print(f'Общая ОЗУ кластера = {round(self.max_mem / 1024 ** 3)} GB')
        print(f'Занятая ОЗУ кластера = {int(self.mem / 1024 ** 3)} GB')
        print(f'Средняя загрузка ОЗУ кластера = {round(self.mem_load * 100, 2)} %')
        print(f'Количество CPU кластера = {self.maxcpu} шт.')
        print(f'Средняя загрузка CPU кластера = {round(self.cpu_load * 100, 2)} %')
        print(f'Количество хостов в кластере: {len(self.hosts)}')


class Host:
    def __init__(self, host_mem: int, host_mem_usage: int, host_cpu: int, host_cpu_usage: float, name: str, cluster):
        self.name = name
        self.memory = host_mem  # byte
        self.mem_used = host_mem_usage  # byte
        self.mem_load: float = self.mem_used / self.memory  # от 0 до 1
        self.mem_free_real = host_mem - host_mem_usage
        self.cpu = host_cpu
        self.cpu_usage = host_cpu_usage  # от 0 до 1
        self.cluster = cluster
        self.free_cpu = self.host_free_cpu()
        self.free_memory = self.host_free_memory()
        self.vms = set()  # Все виртуальные машины и контейнеры хоста
        self.lxcs = set()  # Только контейнеры хоста
        self.host_vms()
        self.show()

    def host_vms(self):
        """Выбираем виртуальные машины/контейнеры данного хоста.
           Selecting virtual machines/containers of this host."""
        for vm, values in self.cluster.vms.items():
            if values[5] == self.name:
                self.vms.add(vm)
        for lxc, values in self.cluster.lxcs.items():
            if values[5] == self.name:
                self.vms.add(lxc)
                self.lxcs.add(lxc)

    def vm_local_source(self):
        not_migratable_vm = set()
        vm_only = self.vms - self.lxcs
        for vm in vm_only:
            url = f'{self.cluster.server}/api2/json/nodes/{self.name}/qemu/{vm}/migrate'
            check_request = requests.get(url, cookies=payload, verify=False)
            local_disk = (check_request.json()['data']['local_disks'])
            if local_disk:
                not_migratable_vm.add(vm)
        return not_migratable_vm

    # def test_vm_migration(self, recipient, vm, lxc_flag=False):
    #     """Тестовый метод-заглушка для vm_migration().
    #        The test method is a stub for vm_migration()"""
    #     print(f'Процесс миграции {vm}...')

    def vm_migration(self, recipient, vm, lxc_flag=False):
        print()
        print(f'Запрос на миграцию {vm}')
        if lxc_flag:
            options = {'target': recipient, 'restart': 1}
            url = f'{self.cluster.server}/api2/json/nodes/{self.name}/lxc/{vm}/migrate'
        else:
            options = {'target': recipient, 'online': 1}
            url = f'{self.cluster.server}/api2/json/nodes/{self.name}/qemu/{vm}/migrate'
        job = requests.post(url, cookies=payload, headers=header, data=options, verify=False)
        if job.ok:
            print('Миграция...')
            pid = job.json()['data']
        else:
            print(f'Ошибка при запросе миграции VM {vm} с {self.name} на {recipient}. Проверьте запрос.')
            sys.exit()
        status = True
        while status:
            sleep(10)
            url = f'{self.cluster.server}/api2/json/cluster/tasks'
            request = requests.get(url, cookies=payload, verify=False)
            print(request.status_code)
            tasks = request.json()['data']
            for task in tasks:
                if task['upid'] == pid:
                    print(f'UPID: {pid[5:]}')
                    print(f"PID: {task.get('pid')}")
                    print(f'STATUS: {task.get("status")}')
                    print("**************************")
            for task in tasks:
                if task['upid'] == pid and task.get('status') == 'OK':
                    print(f'{pid} - Завершена!')
                    status = False
                    break
                elif task['upid'] == pid and not task.get('pid'):
                    print('Миграция...')
                    break

    def host_free_memory(self):
        if self.mem_load >= THRESHOLD:
            free_memory = 0
        else:
            free_memory = int(self.memory * (THRESHOLD - self.mem_load))
        return int(free_memory)

    def host_free_cpu(self):
        if self.cpu_usage >= THRESHOLD:
            free_cpu = 0
        else:
            free_cpu = self.cpu * (THRESHOLD - self.cpu_usage)
        return free_cpu

    def show(self):
        print('*************************************************')
        print(f'Хост -', self.name)
        print(f'Общая ОЗУ хоста - {round(self.memory / 1024 ** 3)} GB')
        print(f'Занятая ОЗУ хоста - {int(self.mem_used / 1024 ** 3)} GB')
        print(f'Загрузка хоста - {round(self.mem_load * 100, 2)}%')
        # print(f'Процессоров у хоста - {self.cpu} шт.')
        # print(f'Загрузка CPU хоста - {round(self.cpu_usage * 100, 2)} %')
        print(f'Виртуальные машины/контейнеры хоста:')
        print(f'{len(self.vms)} шт.: {self.vms}')
        # print(f'Свободно ядер ~ {int(self.free_cpu)}')
        # print(f'Свободно памяти ~ {int(self.free_memory / 1024 ** 3)} GB')


"""Создаём кластер / Creating a cluster"""
cluster = Cluster(server, auth)


def cluster_load_verification():
    """Проверяем загрузку ОЗУ кластера.
       Checking the cluster RAM load."""
    assert 0 < cluster.mem_load < 1, f'(RU) Загрузка ОЗУ кластера должна быть в диапазоне от 0 до 1 / ' \
                                     f'(EN) The cluster RAM load should be in the range from 0 to 1'
    if cluster.mem_load >= THRESHOLD:
        print(f'(RU) Загрузка кластера {round(cluster.mem_load * 100, 2)} %. Невозможно автоматически освободить хост.')
        print(f'(EN) Cluster load is {round(cluster.mem_load * 100, 2)} %. The host cannot be released automatically.')
        sys.exit()


def host_selection() -> object:
    """Определяем хост, который нужно освободить.
       Determine the host that needs to be released."""
    hosts = {}
    for num, host in enumerate(cluster.hosts, start=1):
        print(f'{num}) {host.name}')
        hosts[num] = host
    select = int(input(f'Введите № хоста, который нужно освободить: '))
    for num, host in hosts.items():
        if num == select:
            print(f'Выбран {host.name}')
            return host
    else:
        print(f'(RU) Неверный ввод. Повторите попытку')
        print(f'(EN) Invalid input. Try again')
        sleep(1)
        return host_selection()


def maintenance_possibility(host: object):
    """Проверяем достаточно ли в кластере свободных ресурсов для размещения виртуальных машин с освобождаемого хоста.
       Checking whether there are enough free resources in the cluster to host virtual machines from the host being
       released."""
    if cluster.free_mem - host.mem_free_real * THRESHOLD < host.mem_used * RISK:
        print(f'(RU) Недостаточно свободного ОЗУ кластера чтобы освободить {host.name}')
        print(f'(EN) There are not enough free cluster memory to free up the {host.name}')
        sys.exit()
    elif cluster.free_cpu < host.cpu * host.cpu_usage * RISK:
        print(f'(RU) Недостаточно свободных процессоров кластера чтобы освободить {host.name}')
        print(f'(EN) There are not enough free cluster CPU to free up the {host.name}')
        sys.exit()
    else:
        pass


def lxc_verification(host: object):
    """Проверяем наличие контейнеров на освобождаемом хосте.
       Checking the presence of the container on the host being released."""
    if host.lxcs:
        print('*******************************************************************************************************')
        print(f'(RU) Данный хост содержит контейнеры. Нужно иметь ввиду что контейнеры при миграции перезагружаются')
        print(f'(EN) This host contains containers. It should be borne in mind that containers are restarted during '
              f'migration')
        print('*******************************************************************************************************')
        print(f'LXCs: {host.lxcs}')
        choice = input('Напишите "YES" для продолжения / Type "YES" to continue: ')
        if choice == "YES":
            pass
        else:
            print(f'(RU) Перенесите контейнеры вручную и перезапустите скрипт')
            print(f'(EN) Move the containers manually and restart the script')
            sys.exit()
    pass


def vms_local_sources_verification(host: object):
    """Проверяем наличие локальных ресурсов у виртуальных машин, препятствующих миграции.
       Checking the availability of local resources for virtual machines that prevent migration."""
    print()
    print(f'(RU) Проверяем наличие локальных ресурсов у VM...')
    print(f'(EN) Checking the availability of local resources from the VM...')
    print()
    check: set = host.vm_local_source()
    if check:
        print(f'(RU) Эти VM {check} имеют локальные ресурсы. Это могут быть CD-ROM или локальные диски,')
        print(f'размещенные на хосте. В первом случае нужно отключить диск, во втором - перенести машину')
        print(f'вручную указав новое расположение для дисков. Затем перезапустите скрипт.')
        print('-------------------------------------------------------------------------------------------------------')
        print(f'(EN) These VMs {check} have local resources. These can be CD-ROMs or local disks hosted on the host.')
        print(f'In the first case, you need to disconnect the disk, in the second case, you need to manually move')
        print(f'the machine by specifying a new location for the disks. Then restart the script.')
        sys.exit()
    pass


def main_job(host: object):
    recipients_dict = {}
    migrating_vm_dict = {}
    cluster.hosts.remove(host)
    for _host in cluster.hosts:
        recipients_dict[_host.name] = _host.free_memory
    for vm in host.vms:
        migrating_vm_dict[vm] = cluster.vms[vm][2]

    def test(recipients, vms):
        cl_d = deepcopy(recipients)
        vm_d = deepcopy(vms)
        for _vm in vms:
            free_mem, recipient = max(zip(cl_d.values(), cl_d.keys()))
            vm_mem, vm = max(zip(vm_d.values(), vm_d.keys()))
            if free_mem > vm_mem:
                print(f'(RU) Производим проверочные вычисления для VM {vm} и реципиента {recipient}')
                print(f'(EN) Verification calculations are performed for the VM {vm} and recipient {recipient}')
                cl_d[recipient] = cl_d[recipient] - vm_mem
                del vm_d[vm]
            else:
                print(f'(RU) Виртуальная машина {vm} не помещается на максимально свободный хост {recipient}')
                sys.exit()
        else:
            print(f'(RU) Всё готово для начала миграции VM!')
            print(f'(EN) Everything is ready to start VM migration!')
            for i in range(5, 0, -1):
                print(f'Начинаем через / Start in {i}...')
                sleep(1)

    def migration(recipients, vms):
        cl_d = deepcopy(recipients)
        vm_d = deepcopy(vms)
        for _vm in vms:
            free_mem, recipient = max(zip(cl_d.values(), cl_d.keys()))
            vm_mem, vm = max(zip(vm_d.values(), vm_d.keys()))
            lxc_flag = True if vm in host.lxcs else False
            if free_mem > vm_mem:
                print(f'Мигрируем VM {vm} на {recipient}')
                host.vm_migration(recipient, vm, lxc_flag)
                cl_d[recipient] = cl_d[recipient] - vm_mem
                del vm_d[vm]
            else:
                print(f'Миграция {vm} не завершена, проверьте состояние хоста.')
                sys.exit()

    test(recipients_dict, migrating_vm_dict)
    migration(recipients_dict, migrating_vm_dict)


cluster_load_verification()
selected_host = host_selection()
maintenance_possibility(selected_host)
lxc_verification(selected_host)
vms_local_sources_verification(selected_host)
main_job(selected_host)
new_cluster = Cluster(server, auth)
print()
print(f'{selected_host.name} освобождён!')
