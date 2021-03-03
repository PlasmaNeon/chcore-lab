/*
 * Copyright (c) 2020 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * OS-Lab-2020 (i.e., ChCore) is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *   http://license.coscl.org.cn/MulanPSL
 *   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 *   PURPOSE.
 *   See the Mulan PSL v1 for more details.
 */

#include <common/mm.h>
#include <common/kprint.h>
#include <common/macro.h>

#include "buddy.h"
#include "slab.h"

extern unsigned long *img_end;

#define PHYSICAL_MEM_START (24*1024*1024)	//24M

#define START_VADDR phys_to_virt(PHYSICAL_MEM_START)	//24M
#define NPAGES (128*1000)

#define PHYSICAL_MEM_END (PHYSICAL_MEM_START+NPAGES*BUDDY_PAGE_SIZE)

/*
 * Layout:
 *
 * | metadata (npages * sizeof(struct page)) | start_vaddr ... (npages * PAGE_SIZE) |
 *
 */

unsigned long get_ttbr1(void)
{
	unsigned long pgd;

	__asm__("mrs %0,ttbr1_el1":"=r"(pgd));
	return pgd;
}

/*
 * map_kernel_space: map the kernel virtual address
 * [va:va+size] to physical addres [pa:pa+size].
 * 1. get the kernel pgd address
 * 2. fill the block entry with corresponding attribution bit
 *
 */
void map_kernel_space(vaddr_t va, paddr_t pa, size_t len)
{
	// <lab2>

	//From mmu.c
	#define IS_VALID (1UL << 0)
	#define UXN	       (0x1UL << 54)
	#define ACCESSED       (0x1UL << 10)
	#define INNER_SHARABLE (0x3UL << 8)
	#define NORMAL_MEMORY  (0x4UL << 2)
	
	// From page_table.h
	#define PAGE_SHIFT                          (12)
	#define PAGE_MASK                           (PAGE_SIZE - 1)
	#define PAGE_ORDER                          (9)
	#define PTP_INDEX_MASK			    ((1 << (PAGE_ORDER)) - 1)
	#define L0_INDEX_SHIFT			    ((3 * PAGE_ORDER) + PAGE_SHIFT)
	#define L1_INDEX_SHIFT			    ((2 * PAGE_ORDER) + PAGE_SHIFT)
	#define L2_INDEX_SHIFT			    ((1 * PAGE_ORDER) + PAGE_SHIFT)
	#define L3_INDEX_SHIFT			    ((0 * PAGE_ORDER) + PAGE_SHIFT)

	#define GET_L0_INDEX(addr) ((addr >> L0_INDEX_SHIFT) & PTP_INDEX_MASK)
	#define GET_L1_INDEX(addr) ((addr >> L1_INDEX_SHIFT) & PTP_INDEX_MASK)
	#define GET_L2_INDEX(addr) ((addr >> L2_INDEX_SHIFT) & PTP_INDEX_MASK)
	#define GET_L3_INDEX(addr) ((addr >> L3_INDEX_SHIFT) & PTP_INDEX_MASK)
	
	// My macros
	#define SIZE_2M				(1 << 21)
	#define GET_PADDR_IN_PTE(entry) \
	( (((u64)entry >> PAGE_SHIFT) & ((1UL << 36) - 1)) << PAGE_SHIFT)
	// Pick table.next_table_addr (check page_table.h for definition), 
	// table.next_table_addr is 36bits, representing physical page number,  
	// then restore it to 48bits physical address.
	#define GET_NEXT_TABLE_VADDR(entry) \
	phys_to_virt((u64)GET_PADDR_IN_PTE(entry)) // get virtual address.
	
	vaddr_t pgd_addr = phys_to_virt(get_ttbr1()); //L0 page table base address.
	
	vaddr_t* pgd = (vaddr_t*)pgd_addr;
	int entry_idx = GET_L0_INDEX(va); // L0 page table entry
	pgd =(vaddr_t*) GET_NEXT_TABLE_VADDR(pgd[entry_idx]); // L1 page table
	entry_idx = GET_L1_INDEX(va); // L1 page table entry
	pgd = (vaddr_t*) GET_NEXT_TABLE_VADDR(pgd[entry_idx]); //L2 page table

	for (u32 i = GET_L2_INDEX(va); i < GET_L2_INDEX(va) + len / SIZE_2M; i++){
		//Same operations in mmu.c
		pgd[i] = (pa + i * SIZE_2M)
		| UXN	/* Unprivileged execute never */
		| ACCESSED	/* Set access flag */
		| INNER_SHARABLE	/* Sharebility */
		| NORMAL_MEMORY	/* Normal memory */
		| IS_VALID;
	}
	
	// </lab2>
}

void kernel_space_check(void)
{
	unsigned long kernel_val;
	for (unsigned long i = 128; i < 256; i++) {
		kernel_val = *(unsigned long *)(KBASE + (i << 21));
		kinfo("kernel_val: %lx\n", kernel_val);
	}
	kinfo("kernel space check pass\n");
}

struct phys_mem_pool global_mem;

void mm_init(void)
{
	vaddr_t free_mem_start = 0;
	struct page *page_meta_start = NULL;
	u64 npages = 0;
	u64 start_vaddr = 0;

	free_mem_start =
	    phys_to_virt(ROUND_UP((vaddr_t) (&img_end), PAGE_SIZE));
	npages = NPAGES;
	start_vaddr = START_VADDR;
	kdebug("[CHCORE] mm: free_mem_start is 0x%lx, free_mem_end is 0x%lx\n",
	       free_mem_start, phys_to_virt(PHYSICAL_MEM_END));

	if ((free_mem_start + npages * sizeof(struct page)) > start_vaddr) {
		BUG("kernel panic: init_mm metadata is too large!\n");
	}

	page_meta_start = (struct page *)free_mem_start;
	kdebug("page_meta_start: 0x%lx, real_start_vadd: 0x%lx,"
	       "npages: 0x%lx, meta_page_size: 0x%lx\n",
	       page_meta_start, start_vaddr, npages, sizeof(struct page));

	/* buddy alloctor for managing physical memory */
	init_buddy(&global_mem, page_meta_start, start_vaddr, npages);

	/* slab alloctor for allocating small memory regions */
	init_slab();

	map_kernel_space(KBASE + (128UL << 21), 128UL << 21, 128UL << 21);
	printk("Here!\n");
	//check whether kernel space [KABSE + 256 : KBASE + 512] is mapped 
	// kernel_space_check();
}
