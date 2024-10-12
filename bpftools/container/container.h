#ifndef __CONTAINER_H
#define __CONTAINER_H

#include "../process/process.h"

struct container_event {
	struct process_event process;
	unsigned long container_id;
	char container_name[50];
};

#endif