#pragma once
#include "HollowingException.h"

class AllocationException : public HollowingException
{
public:
	using HollowingException::HollowingException;
};
