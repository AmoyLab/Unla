import {
  Table,
  TableHeader,
  TableColumn,
  TableBody,
  TableRow,
  TableCell,
  Button,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  useDisclosure,
  Input,
  Select,
  SelectItem,
  Switch,
  Modal,
} from '@heroui/react';
import { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import LocalIcon from '@/components/LocalIcon';
import { MultiSelectAutocomplete } from "@/components/ui/MultiSelectAutocomplete";
import { getUsers, createUser, updateUser, deleteUser, toggleUserStatus, getTenants, getUserWithTenants } from '@/services/api';
import {User, Tenant, CreateUserForm, UpdateUserForm} from '@/types/user';

export function UserManagement() {
  const { t } = useTranslation();
  const [users, setUsers] = useState<User[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [userToDelete, setUserToDelete] = useState<string>('');
  const [createForm, setCreateForm] = useState<CreateUserForm>({
    username: '',
    password: '',
    role: 'normal',
    tenantIds: [],
  });
  const [updateForm, setUpdateForm] = useState<UpdateUserForm>({
    username: '',
    tenantIds: [],
  });

  const {
    isOpen: isCreateOpen,
    onOpen: onCreateOpen,
    onClose: onCreateClose,
  } = useDisclosure();
  const {
    isOpen: isUpdateOpen,
    onOpen: onUpdateOpen,
    onClose: onUpdateClose,
  } = useDisclosure();
  const {
    isOpen: isDeleteOpen,
    onOpen: onDeleteOpen,
    onClose: onDeleteClose,
  } = useDisclosure();

  const fetchTenants = useCallback(async () => {
    try {
      const data = await getTenants();
      setTenants(data);
    } catch {
      // Error already handled in the API function
    }
  }, []);

  const fetchUsers = useCallback(async () => {
    try {
      const data = await getUsers();
      setUsers(data);
    } catch {
      // Error already handled in the API function
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
    fetchTenants();
  }, [fetchUsers, fetchTenants]);

  const handleCreate = async () => {
    try {
      await createUser(createForm);
      onCreateClose();
      fetchUsers();
      setCreateForm({ username: '', password: '', role: 'normal', tenantIds: [] });
    } catch {
      // Error already handled in the API function
    }
  };

  const handleUpdate = async () => {
    if (!selectedUser) return;
    try {
      await updateUser(updateForm);
      onUpdateClose();
      fetchUsers();
      setSelectedUser(null);
      setUpdateForm({ username: '', tenantIds: [] });
    } catch {
      // Error already handled in the API function
    }
  };

  const openDeleteConfirm = (username: string) => {
    setUserToDelete(username);
    onDeleteOpen();
  };

  const handleDelete = async () => {
    try {
      await deleteUser(userToDelete);
      onDeleteClose();
      fetchUsers();
    } catch {
      // Error already handled in the API function
    }
  };

  const handleEdit = async (user: User) => {
    try {
      const userData = await getUserWithTenants(user.username);
      setSelectedUser(userData);
      setUpdateForm({
        username: userData.username,
        role: userData.role,
        isActive: userData.isActive,
        tenantIds: userData.tenants?.map((t: Tenant) => t.id) || [],
      });
      onUpdateOpen();
    } catch {
      // Error already handled in the API function
    }
  };

  const handleToggleStatus = async (user: User) => {
    try {
      await toggleUserStatus(user.username, !user.isActive);
      fetchUsers();
    } catch {
      // Error already handled in the API function
    }
  };

  // Create tenant ID to tenant object mapping for easy lookup
  const tenantsMap = useMemo(() => {
    const map = new Map<number, Tenant>();
    tenants.forEach(tenant => {
      map.set(tenant.id, tenant);
    });
    return map;
  }, [tenants]);

  // Get tenant items for MultiSelectAutocomplete
  const getTenantItems = useCallback(() => {
    return tenants
      .filter(tenant => tenant.isActive)
      .map(tenant => `${tenant.name}(${tenant.prefix})`);
  }, [tenants]);

  // Get selected tenant items for MultiSelectAutocomplete
  const getSelectedTenantItems = useCallback((tenantIds: number[] = []) => {
    return tenantIds.map(id => {
      const tenant = tenantsMap.get(id);
      return tenant ? `${tenant.name}(${tenant.prefix})` : '';
    }).filter(Boolean);
  }, [tenantsMap]);

  // Handle tenant selection for MultiSelectAutocomplete component
  const handleCreateTenantSelect = (selectedTenantNames: string[]) => {
    const tenantIds = selectedTenantNames.map(name => {
      const tenant = tenants.find(t => `${t.name}(${t.prefix})` === name);
      return tenant?.id;
    }).filter((id): id is number => id !== undefined);
    
    setCreateForm({
      ...createForm,
      tenantIds
    });
  };

  const handleUpdateTenantSelect = (selectedTenantNames: string[]) => {
    const tenantIds = selectedTenantNames.map(name => {
      const tenant = tenants.find(t => `${t.name}(${t.prefix})` === name);
      return tenant?.id;
    }).filter((id): id is number => id !== undefined);
    
    setUpdateForm({
      ...updateForm,
      tenantIds
    });
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">{t('users.title')}</h1>
        <Button
          color="primary"
          startContent={<LocalIcon icon="lucide:plus" />}
          onPress={onCreateOpen}
        >
          {t('users.add')}
        </Button>
      </div>

      <Table aria-label={t('users.title')}>
        <TableHeader>
          <TableColumn>{t('users.username')}</TableColumn>
          <TableColumn>{t('users.role')}</TableColumn>
          <TableColumn>{t('users.status')}</TableColumn>
          <TableColumn>{t('users.created_at')}</TableColumn>
          <TableColumn>{t('users.actions')}</TableColumn>
        </TableHeader>
        <TableBody
          loadingContent={<div>{t('common.loading')}</div>}
          loadingState={loading ? 'loading' : 'idle'}
        >
          {users.map((user) => (
            <TableRow key={user.id}>
              <TableCell>{user.username}</TableCell>
              <TableCell>{user.role === 'admin' ? t('users.role_admin') : t('users.role_normal')}</TableCell>
              <TableCell>
                <span
                  className={`px-2 py-1 rounded-full text-xs ${
                    user.isActive
                      ? 'bg-success-100 text-success-800'
                      : 'bg-danger-100 text-danger-800'
                  }`}
                >
                  {user.isActive ? t('users.status_enabled') : t('users.status_disabled')}
                </span>
              </TableCell>
              <TableCell>
                {new Date(user.createdAt).toLocaleString()}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <Switch
                      size="sm"
                      isSelected={user.isActive}
                      onValueChange={() => handleToggleStatus(user)}
                    />
                    <span className="text-sm text-gray-600">
                      {user.isActive ? t('users.status_enabled') : t('users.status_disabled')}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="light"
                      onPress={() => handleEdit(user)}
                    >
                      {t('users.edit')}
                    </Button>
                    <Button
                      size="sm"
                      color="danger"
                      variant="light"
                      onPress={() => openDeleteConfirm(user.username)}
                    >
                      {t('users.delete')}
                    </Button>
                  </div>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* Create User Modal */}
      <Modal isOpen={isCreateOpen} onClose={onCreateClose} size="lg">
        <ModalContent>
          <ModalHeader>{t('users.add')}</ModalHeader>
          <ModalBody>
            <div className="flex flex-col gap-4">
              <Input
                label={t('users.username')}
                value={createForm.username}
                onChange={(e) =>
                  setCreateForm({ ...createForm, username: e.target.value })
                }
              />
              <Input
                label={t('users.password')}
                type="password"
                value={createForm.password}
                onChange={(e) =>
                  setCreateForm({ ...createForm, password: e.target.value })
                }
              />
              <Select
                label={t('users.role')}
                selectedKeys={[createForm.role]}
                onSelectionChange={(keys) => {
                  const newRole = Array.from(keys)[0] as 'admin' | 'normal';
                  setCreateForm({
                    ...createForm,
                    role: newRole,
                    // Clear tenant associations when switching to admin role
                    tenantIds: newRole === 'admin' ? [] : createForm.tenantIds,
                  });
                }}
              >
                <SelectItem key="admin" textValue={t('users.role_admin')}>{t('users.role_admin')}</SelectItem>
                <SelectItem key="normal" textValue={t('users.role_normal')}>{t('users.role_normal')}</SelectItem>
              </Select>

              {/* Tenant selection section */}
              {createForm.role === 'normal' && (
                <div className="mt-2">
                  <MultiSelectAutocomplete
                    items={getTenantItems()}
                    label={t('users.select_tenants')}
                    selectedItems={getSelectedTenantItems(createForm.tenantIds)}
                    onSelectionChange={handleCreateTenantSelect}
                    allowCustomValues={false}
                    className="mb-4"
                  />
                </div>
              )}
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="light" onPress={onCreateClose}>
              {t('common.cancel')}
            </Button>
            <Button
              color="primary"
              onPress={handleCreate}
              isDisabled={
                !createForm.username || 
                !createForm.password ||
                (createForm.role === 'normal' && (!createForm.tenantIds || createForm.tenantIds.length === 0))
              }
            >
              {t('common.create')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Update User Modal */}
      <Modal isOpen={isUpdateOpen} onClose={onUpdateClose} size="lg">
        <ModalContent>
          <ModalHeader>{t('users.edit')}</ModalHeader>
          <ModalBody>
            <div className="flex flex-col gap-4">
              <Input
                label={t('users.username')}
                value={updateForm.username}
                isReadOnly
              />
              <Input
                label={t('users.password')}
                type="password"
                placeholder={t('users.password_placeholder')}
                value={updateForm.password || ''}
                onChange={(e) =>
                  setUpdateForm({ ...updateForm, password: e.target.value })
                }
              />
              <Select
                label={t('users.role')}
                selectedKeys={[updateForm.role || '']}
                onSelectionChange={(keys) => {
                  const newRole = Array.from(keys)[0] as 'admin' | 'normal';
                  setUpdateForm({
                    ...updateForm,
                    role: newRole,
                    // Clear tenant associations when switching to admin role
                    tenantIds: newRole === 'admin' ? [] : updateForm.tenantIds,
                  });
                }}
              >
                <SelectItem key="admin" textValue={t('users.role_admin')}>{t('users.role_admin')}</SelectItem>
                <SelectItem key="normal" textValue={t('users.role_normal')}>{t('users.role_normal')}</SelectItem>
              </Select>

              <div className="flex items-center gap-2">
                <Switch
                  isSelected={updateForm.isActive}
                  onValueChange={(checked) =>
                    setUpdateForm({ ...updateForm, isActive: checked })
                  }
                />
                <span>
                  {updateForm.isActive ? t('users.status_enabled') : t('users.status_disabled')}
                </span>
              </div>

              {/* Tenant selection section */}
              {updateForm.role === 'normal' && (
                <div className="mt-2">
                  <MultiSelectAutocomplete
                    items={getTenantItems()}
                    label={t('users.select_tenants')}
                    selectedItems={getSelectedTenantItems(updateForm.tenantIds)}
                    onSelectionChange={handleUpdateTenantSelect}
                    allowCustomValues={false}
                    className="mb-4"
                  />
                </div>
              )}
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="light" onPress={onUpdateClose}>
              {t('common.cancel')}
            </Button>
            <Button color="primary" onPress={handleUpdate}>
              {t('common.save')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal isOpen={isDeleteOpen} onClose={onDeleteClose}>
        <ModalContent>
          <ModalHeader className="flex flex-col gap-1">{t('users.delete_title')}</ModalHeader>
          <ModalBody>
            <p>{t('users.confirm_delete')}</p>
            <p className="text-danger font-semibold">{userToDelete}</p>
          </ModalBody>
          <ModalFooter>
            <Button variant="light" onPress={onDeleteClose}>
              {t('common.cancel')}
            </Button>
            <Button color="danger" onPress={handleDelete}>
              {t('users.delete')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </div>
  );
}
