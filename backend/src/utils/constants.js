export const UserRolesEnum = {
  ADMIN: 'admin',
  PROJECT_ADMIN: 'project_admin',
  MEMBER: 'member'
}

export const AvailabeUserRoles = Object.values(UserRolesEnum) //* returns array of values

export const TaskStatusEnum = {
  TODO: "todo",
  IN_PROGRESS: "in_progress",
  DONE: "done"
}

export const AvailabeTaskStatus = Object.values(TaskStatusEnum)