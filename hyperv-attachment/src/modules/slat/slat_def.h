#pragma once
#include "ia32-doc/ia32.hpp"

#ifdef _INTELMACHINE
using slat_pml4e = ept_pml4e;
using slat_pdpte_1gb = ept_pdpte_1gb;
using slat_pdpte = ept_pdpte;
using slat_pde_2mb = ept_pde_2mb;
using slat_pde = ept_pde;
using slat_pte = ept_pte;
#else
using slat_pml4e = pml4e_64;
using slat_pdpte_1gb = pdpte_1gb_64;
using slat_pdpte = pdpte_64;
using slat_pde_2mb = pde_2mb_64;
using slat_pde = pde_64;
using slat_pte = pte_64;
#endif
