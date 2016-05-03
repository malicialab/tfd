/* 
 *  hooks for memory allocation and deallocation
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _GROUP_ALLOC_H_
#define _GROUP_ALLOC_H_

void malloc_call(void *opaque);
void malloc_ret(void *opaque);
void calloc_call(void *opaque);
void calloc_ret(void *opaque);
void free_call(void *opaque);
void free_ret(void *opaque);
void realloc_call(void *opaque);
void realloc_ret(void *opaque);
void posix_memalign_call(void *opaque);
void posix_memalign_ret(void *opaque);
void memalign_call(void *opaque);
void memalign_ret(void *opaque);
void heap_create_call(void *opaque);
void heap_create_ret(void *opaque);
void rtl_create_heap_call(void *opaque);
void rtl_create_heap_ret(void *opaque);
void rtl_allocate_heap_call(void *opaque);
void rtl_allocate_heap_ret(void *opaque);
void rtl_free_heap_call(void *opaque);
void rtl_free_heap_ret(void *opaque);
void rtl_reallocate_heap_call(void *opaque);
void rtl_reallocate_heap_ret(void *opaque);
void zw_map_view_of_section_call(void *opaque);
void zw_map_view_of_section_ret(void *opaque);
void zw_unmap_view_of_section_call(void *opaque);
void zw_unmap_view_of_section_ret(void *opaque);
void zw_allocate_virtual_memory_call(void *opaque);
void zw_allocate_virtual_memory_ret(void *opaque);
void virtual_alloc_call(void *opaque);
void virtual_alloc_ret(void *opaque);
void virtual_free_call(void *opaque);
void virtual_free_ret(void *opaque);
void local_alloc_call(void *opaque);
void local_alloc_ret(void *opaque);
void local_realloc_call(void *opaque);
void local_realloc_ret(void *opaque);
void local_free_call(void *opaque);
void local_free_ret(void *opaque);
void cf_allocator_allocate_call(void *opaque);
void cf_allocator_allocate_ret(void *opaque);
void cf_allocator_deallocate_call(void *opaque);
void cf_allocator_deallocate_ret(void *opaque);
void cf_allocator_reallocate_call(void *opaque);
void cf_allocator_reallocate_ret(void *opaque);
void sqlite3_db_alloc_call(void *opaque);
void sqlite3_db_alloc_ret(void *opaque);
void sqlite3_db_free_call(void *opaque);
void sqlite3_db_free_ret(void *opaque);
void sqlite3_db_realloc_call(void *opaque);
void sqlite3_db_realloc_ret(void *opaque);
void g_slice_free1_call(void *opaque);
void g_slice_free1_ret(void *opaque);
void g_slice_free_chain_with_offset_call(void *opaque);
void g_slice_free_chain_with_offset_ret(void *opaque);

#endif // #ifndef _GROUP_ALLOC_H_

