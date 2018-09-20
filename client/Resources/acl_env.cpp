#include "acl_env.h"
#include <iostream>


void view_accrights(DWORD Mask)
{
	for (int i = 0; i < 21; i++)
	{
		if (AccessRightArray[i] & Mask)
			std::cout << "#" << access_right(AccessRightArray[i]) << std::endl;
	}

}

const char *access_right(DWORD Mask)
{
	switch (Mask)
	{
	case GENERIC_READ:
		return "GENERIC_READ";
	case GENERIC_WRITE:
		return "GENERIC_WRITE";
	case GENERIC_EXECUTE:
		return "GENERIC_EXECUTE";
	case GENERIC_ALL:
		return "GENERIC_ALL";
	case DELETE:
		return "DELETE";
	case READ_CONTROL:
		return "READ_CONTROL";
	case WRITE_DAC:
		return "WRITE_DAC";
	case WRITE_OWNER:
		return "WRITE_OWNER";
	case SYNCHRONIZE:
		return "SYNCHRONIZE";
	case STANDARD_RIGHTS_REQUIRED:
		return "STANDARD_RIGHTS_REQUIRED";
	case STANDARD_RIGHTS_ALL:
		return "STANDARD_RIGHTS_ALL";
	case ACTRL_DS_OPEN:
		return "ACTRL_DS_OPEN";
	case ACTRL_DS_CREATE_CHILD:
		return "ACTRL_DS_CREATE_CHILD";
	case ACTRL_DS_DELETE_CHILD:
		return "ACTRL_DS_DELETE_CHILD";
	case ACTRL_DS_LIST:
		return "ACTRL_DS_LIST";
	case ACTRL_DS_READ_PROP:
		return "ACTRL_DS_READ_PROP";
	case ACTRL_DS_WRITE_PROP:
		return "ACTRL_DS_WRITE_PROP";
	case ACTRL_DS_SELF:
		return "ACTRL_DS_SELF";
	case ACTRL_DS_DELETE_TREE:
		return "ACTRL_DS_DELETE_TREE";
	case ACTRL_DS_LIST_OBJECT:
		return "ACTRL_DS_LIST_OBJECT";
	case ACTRL_DS_CONTROL_ACCESS:
		return "ACTRL_DS_CONTROL_ACCESS";
	default:
		return "UNKNOWN RIGHT";
		break;
	}
}

DWORD AccessRightArray[] = {
	GENERIC_READ,
	GENERIC_WRITE,
	GENERIC_EXECUTE,
	GENERIC_ALL,
	DELETE,
	READ_CONTROL,
	WRITE_DAC,
	WRITE_OWNER,
	SYNCHRONIZE,
	STANDARD_RIGHTS_REQUIRED,
	STANDARD_RIGHTS_ALL,
	ACTRL_DS_OPEN,
	ACTRL_DS_CREATE_CHILD,
	ACTRL_DS_DELETE_CHILD,
	ACTRL_DS_LIST,
	ACTRL_DS_READ_PROP,
	ACTRL_DS_WRITE_PROP,
	ACTRL_DS_SELF,
	ACTRL_DS_DELETE_TREE,
	ACTRL_DS_LIST_OBJECT,
	ACTRL_DS_CONTROL_ACCESS };
