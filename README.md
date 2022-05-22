# Proxmox-host-maintenance-mode v0.6.3 (Run in PyCharm)


(EN) This script allows you to prepare the Proxmox host for maintenance. After the launch, you are prompted to select a host. Next, checks are carried out for the availability of free cluster resources, the presence of containers (lxc), as they are rebooted during migration. It also checks the availability of local resources for the VM, because they do not allow the VM to migrate. If all the checks are passed, the migration begins. The result should be a completely free host. The larger the cluster and the more free resources and the smaller the size of the virtual machines, the greater the probability of a positive outcome. It is not difficult to create conditions under which the script will not be able to work correctly. But it works correctly on a large cluster.
Sorry for the Google translate)

(RU) Данный скрипт позволяет подготовить хост Proxmox для обслуживания. После запуска предлагается выбрать хост. Далее проводятся проверки на наличие свободных ресурсов кластера, наличие контейнеров (lxc), так как они перезагружаются во время миграции.  Также проверяется наличие локальных ресурсов у VM, т.к. они не позволяют мигрировать VM. Если все проверки пройдены - начинается миграция. Результатом должен быть полностью свободный хост. Чем больше кластер и больше свободных ресурсов и чем меньше размеры виртуальных машин, тем больше вероятность положительного исхода. Не сложно создать условия при которых скрипт не сможет корректно отработать. Но на большом кластере он работает корректно.

Before:
![1](https://user-images.githubusercontent.com/88323643/145380080-82619b50-d201-4fb5-b1a1-8373a67d7019.png)
After:
![2](https://user-images.githubusercontent.com/88323643/145380094-86b74535-5f42-4a5f-bcc6-b0014b693619.png)


Changelog:

**0.6** (24.03.2022)

1.Redesigned the mechanism for determining the end of VM migration.  
2.Added voice notification (not tested on Linux server versions).

# Running the script is tested on:
1. PyCharm 2021+, Python 3.10+, Win10
