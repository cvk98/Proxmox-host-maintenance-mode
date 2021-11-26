# Proxmox-host-maintenance-mode

(EN) This script allows you to prepare the Proxmox host for maintenance. After the launch, you are prompted to select a host. Next, checks are carried out for the availability of free cluster resources, the presence of containers (lxc), as they are rebooted during migration. It also checks the availability of local resources for the VM, because they do not allow the VM to migrate. If all the checks are passed, the migration begins. The result should be a completely free host.

(RU) Данный скрипт позволяет подготовить хост Proxmox для обслуживания. После запуска предлагается выбрать хост. Далее проводятся проверки на наличие свободных ресурсов кластера, наличие контейнеров (lxc), так как они перезагружаются во время миграции.  Также проверяется наличие локальных ресурсов у VM, т.к. они не позволяют мигрировать VM. Если все проверки пройдены - начинается миграция. Результатом должен быть полностью свободный хост.
