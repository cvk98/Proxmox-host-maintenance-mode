import sys
import requests
import urllib3
from threading import Thread
from time import sleep
from copy import deepcopy
from prettytable import PrettyTable
from localisation import *

server = "https://10.10.10.100:8006"
auth = {'username': "root@pam", 'password': "YOUR_PASSWORD"}
message = EN  # Localisation (RU, EN, GR)

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

    def __authorization(self):
        """Авторизация и получение токена и тикета.
           Authorization and receipt of a token and ticket."""
        global payload, header
        url = f'{self.server}/api2/json/access/ticket'
        print(message[1])
        get_token = requests.post(url, data=self._data, verify=False)
        if get_token.ok:
            print(message[2].format(get_token.status_code))
        else:
            print(message[3], format(get_token.status_code, get_token.reason))
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
        print(message[4])
        resources_request = requests.get(url, cookies=payload, verify=False)
        if resources_request.ok:
            print(message[5].format(resources_request.status_code))
        else:
            print(message[6].format(resources_request.status_code, resources_request.reason))
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
            print(message[7])
            print(message[8])
            sys.exit()
        elif self.mem_load > 1:
            print(message[9].format(self.mem_load))
            raise ValueError
        if self.cpu_load > 1:
            print(message[10].format(self.cpu_load))
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
            print(message[11])
            sys.exit()

    def cluster_hosts(self):
        """Создаём хосты подставляя данные из кластера.
           Creating hosts by substituting data from the cluster."""
        hosts: list = []
        for host, item in self.cluster_dict.items():
            host = Host(item[0], item[1], item[2], item[3], str(host), self)
            hosts.append(host)
        return hosts


class Host:
    def __init__(self, host_mem: int, host_mem_usage: int, host_cpu: int, host_cpu_usage: float, name, cluster_obj):
        self.name = name
        self.memory = host_mem  # byte
        self.mem_used = host_mem_usage  # byte
        self.mem_load: float = self.mem_used / self.memory  # от 0 до 1
        self.mem_free_real = host_mem - host_mem_usage
        self.cpu = host_cpu
        self.cpu_usage = host_cpu_usage  # от 0 до 1
        self.cluster = cluster_obj
        self.free_cpu = self.host_free_cpu()
        self.free_memory = self.host_free_memory()
        self.vms = set()  # Все виртуальные машины и контейнеры хоста
        self.lxcs = set()  # Только контейнеры хоста
        self.host_vms()

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
        thread_list = []
        not_migratable_vm = set()
        vm_only = self.vms - self.lxcs

        def request():
            url = f'{self.cluster.server}/api2/json/nodes/{self.name}/qemu/{vm}/migrate'
            check_request = requests.get(url, cookies=payload, verify=False)
            local_disk = (check_request.json()['data']['local_disks'])
            if local_disk:
                not_migratable_vm.add(vm)
        print(message[42], end='')
        for vm in sorted(vm_only):
            t = Thread(target=request(), name=str(vm))
            t.start()
            print('{}'.format(str(vm)), end='|')
            thread_list.append(t)
        else:
            for t in thread_list:
                t.join()
        return not_migratable_vm

    # def test_vm_migration(self, recipient, vm, lxc_flag=False):
    #     """Тестовый метод-заглушка для vm_migration().
    #        The test method is a stub for vm_migration()"""
    #     print(f'Процесс миграции {vm}...')

    def vm_migration(self, recipient, vm, lxc_flag=False):
        print()
        print(message[12].format(vm))
        if lxc_flag:
            options = {'target': recipient, 'restart': 1}
            url = f'{self.cluster.server}/api2/json/nodes/{self.name}/lxc/{vm}/migrate'
        else:
            options = {'target': recipient, 'online': 1}
            url = f'{self.cluster.server}/api2/json/nodes/{self.name}/qemu/{vm}/migrate'
        job = requests.post(url, cookies=payload, headers=header, data=options, verify=False)
        if job.ok:
            print(message[13])
            pid = job.json()['data']
        else:
            print(message[14].format(vm, self.name, recipient))
            sys.exit()
        status = True
        while status:
            sleep(10)
            url = f'{self.cluster.server}/api2/json/cluster/tasks'
            request = requests.get(url, cookies=payload, verify=False)
            if request.ok:
                tasks = request.json()['data']
                for task in tasks:
                    if task['upid'] == pid:
                        print(f'UPID: {pid[5:]}')
                        print(f"PID: {task.get('pid')}")
                        print(f'STATUS: {task.get("status")}')
                        print("**************************")
                for task in tasks:
                    if task['upid'] == pid and task.get('status') == 'OK':
                        print(message[15].format(pid[5:]))
                        status = False
                        break
                    elif task['upid'] == pid and not task.get('pid'):
                        print(message[13])
                        break
            else:
                print(message[16].format(request.status_code))

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


def cluster_load_verification():
    """Проверяем загрузку ОЗУ кластера.
       Checking the cluster RAM load."""
    assert 0 < cluster.mem_load < 1, message[17]
    if cluster.mem_load >= THRESHOLD:
        print(message[18].format(round(cluster.mem_load * 100, 2)))
        print(f'(EN) Cluster load is {round(cluster.mem_load * 100, 2)} %. The host cannot be released automatically.')
        sys.exit()


def cluster_visualisation(cluster_obj):
    cluster_table = PrettyTable()
    columns = message[19]
    cluster_table.add_column(columns[0], [number for number in range(1, len(cluster_obj.hosts) + 1)])
    cluster_table.add_column(columns[1], [host.name for host in cluster_obj.hosts])
    cluster_table.add_column(columns[2], [round(host.memory / 1024 ** 3) for host in cluster_obj.hosts])
    cluster_table.add_column(columns[3], [round(host.mem_used / 1024 ** 3) for host in cluster_obj.hosts])
    cluster_table.add_column(columns[4], [round(host.mem_load * 100, 2) for host in cluster_obj.hosts])
    cluster_table.add_column(columns[5], [len(host.vms) for host in cluster_obj.hosts])
    cluster_table.add_column(columns[6], [sorted(host.vms) if host.vms else message[20] for host in cluster_obj.hosts])
    cluster_table.align[message[21]] = "l"
    from prettytable import DOUBLE_BORDER
    cluster_table.set_style(DOUBLE_BORDER)
    print(cluster_table)


def host_selection() -> object:
    """Определяем хост, который нужно освободить.
       Determine the host that needs to be released."""
    hosts = {}
    cluster_visualisation(cluster)
    for num, host in enumerate(cluster.hosts, start=1):
        hosts[num] = host
    select = int(input(message[22]))
    for num, host in hosts.items():
        if num == select:
            print(message[23].format(host.name))
            return host
    else:
        print(message[24])
        sleep(1)
        return host_selection()


def maintenance_possibility(host: object):
    """Проверяем достаточно ли в кластере свободных ресурсов для размещения виртуальных машин с освобождаемого хоста.
       Checking whether there are enough free resources in the cluster to host virtual machines from the host being
       released."""
    if cluster.free_mem - host.mem_free_real * THRESHOLD < host.mem_used * RISK:
        print(message[25].format(host.name))
        sys.exit()
    elif cluster.free_cpu < host.cpu * host.cpu_usage * RISK:
        print(message[26].format(host.name))
        sys.exit()
    else:
        pass


def lxc_verification(host: object):
    """Проверяем наличие контейнеров на освобождаемом хосте.
       Checking the presence of the container on the host being released."""
    if host.lxcs:
        print('*******************************************************************************************************')
        print(message[27])
        print('*******************************************************************************************************')
        print(message[28].format(host.lxcs))
        choice = input(message[29])
        if choice == "YES":
            pass
        else:
            print(message[30])
            sys.exit()
    pass


def vms_local_sources_verification(host: object):
    """Проверяем наличие локальных ресурсов у виртуальных машин, препятствующих миграции.
       Checking the availability of local resources for virtual machines that prevent migration."""
    print()
    print(message[31])
    check: set = host.vm_local_source()
    if check:
        print()
        print(message[32].format(check))
        print(message[33])
        print(message[34])
        sys.exit()
    else:
        print()


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
                print(message[35].format(vm, recipient))
                cl_d[recipient] = cl_d[recipient] - vm_mem
                del vm_d[vm]
            else:
                print(message[36].format(vm, recipient))
                sys.exit()
        else:
            print(message[37])
            for i in range(5, 0, -1):
                print(message[38].format(i))
                sleep(1)

    def migration(recipients, vms):
        cl_d = deepcopy(recipients)
        vm_d = deepcopy(vms)
        for _ in vms:
            free_mem, recipient = max(zip(cl_d.values(), cl_d.keys()))
            vm_mem, vm = max(zip(vm_d.values(), vm_d.keys()))
            lxc_flag = True if vm in host.lxcs else False
            if free_mem > vm_mem:
                print(message[39].format(vm, recipient))
                host.vm_migration(recipient, vm, lxc_flag)
                cl_d[recipient] = cl_d[recipient] - vm_mem
                del vm_d[vm]
            else:
                print(message[36].format(vm))
                sys.exit()

    test(recipients_dict, migrating_vm_dict)
    migration(recipients_dict, migrating_vm_dict)


cluster = Cluster(server_url, auth)
cluster_load_verification()
selected_host = host_selection()
maintenance_possibility(selected_host)
lxc_verification(selected_host)
vms_local_sources_verification(selected_host)
main_job(selected_host)
new_cluster = Cluster(server_url, auth)
cluster_visualisation(new_cluster)
print()
print(message[41].format(selected_host.name))
