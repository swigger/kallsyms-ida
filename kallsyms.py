# Linux kernel kallsyms unpacker
# Version 0.2
# Copyright (c) 2010-2013 Igor Skochinsky
#
# This software is provided 'as-is', without any express or implied
# warranty. In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
#    1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
#    2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
#
#    3. This notice may not be removed or altered from any source
#    distribution.

is64 = GetSegmentAttr(here(), SEGATTR_BITNESS) == 2
if is64:
  ptrsize = 8
  alignmask = 0xFF
else:
  ptrsize = 4
  alignmask = 0xF

def do_kallsyms(do_rename, do_dump):
  token_idxs = LocByName("kallsyms_token_index")
  tokens = LocByName("kallsyms_token_table")
  names = LocByName("kallsyms_names")
  addrs = LocByName("kallsyms_addresses")
  namecnt = LocByName("kallsyms_num_syms")
  if namecnt == BADADDR:
    Warning("kallsyms_num_syms is not defined!");
    return
  namecnt = Dword(namecnt)
  if tokens == BADADDR:
    Warning("kallsyms_token_table is not defined!");
    return
  if token_idxs == BADADDR:
    Warning("kallsyms_token_index is not defined!");
    return
  if names == BADADDR:
    Warning("kallsyms_names is not defined!");
    return
  if addrs == BADADDR:
    Warning("kallsyms_addresses is not defined!");
    return
  nametbl = []
  tokentbl = []
  for i in range(256):
    idx = Word(token_idxs+i*2)
    token = GetString(tokens+idx, -1, 0)
    #print "token %d: %s"%(i, token)
    if token == None: token=""
    tokentbl.append(token)

  if do_dump:
    dump = file("ksym","w")
  if names != BADADDR:
    for i in range(namecnt):
      nlen = Byte(names)
      names += 1
      name = ""
      while nlen>0:
        j = Byte(names)
        #print "j: %d, token: %s"%(j, tokentbl[j])
        name += tokentbl[j]
        names += 1
        nlen -= 1
      #print "Name %d: %s"%(i, name)
      #nametbl.append(name)
      if is64:
        addr = Qword(addrs+i*ptrsize)
      else:
        addr = Dword(addrs+i*ptrsize)
      if do_dump:
        dump.write("%08X %s %s\n"%(addr, name[0], name[1:]))
      if do_rename: # and name.find(".") == -1:
        #print "%08X: %s"%(addr, name[1:])
        if isTail(GetFlags(addr)):
          MakeUnkn(addr, DOUNK_SIMPLE)
        idaapi.do_name_anyway(addr, name[1:])
        fn= idaapi.get_func(addr)
        if isCode(GetFlags(addr)):
            if not fn:
                print "%08x not in function: %s %s" % (addr, name[0], name[1:])
            elif fn.startEA!=addr:
                print "%08x not function start: %s %s  in %s" % (addr, name[0], name[1:],  Name(fn.startEA))


  if do_dump:
    dump.close()


#a = 0xC0267D70
#MakeName(a, "kallsyms_num_syms")
#n = Dword(a)
#b = (a - n*4) & ~0xF
#MakeName(b, "kallsyms_addresses")
#b = (a + 16) & ~0xF
#MakeName(b, "kallsyms_names")

kallsyms_num_syms = LocByName("kallsyms_num_syms")
if kallsyms_num_syms == BADADDR:
    Message("Scanning for kallsyms tables...\n")
    a = -1
    first = True
    # typical first pointers in the address table (stext, _sinittext)
    if is64:
        pat = "0xFFFFFFC000081000 0xFFFFFFC000081000"
    else:
        pat = "0xC0008000 0xC0008000"
    while True:
        a = FindBinary(a+1, SEARCH_DOWN|SEARCH_CASE, pat)
        if a == BADADDR:
            if not first or is64:
                break
            else:
                pat = "0xC0008180 0xC0008180 0xC0008180"
                a = -1
                first = False
                continue
        print "%08X: potential kallsyms_addresses" % a
        kallsyms_addresses = a
        b = FindBinary(a+1, SEARCH_DOWN|SEARCH_CASE, "0 0 0 0 0 0 0 0 0 0 0 0")
        if b != BADADDR:
            kallsyms_num_syms = (b + alignmask) & ~alignmask
            table_cnt = Dword(kallsyms_num_syms)
            print "kallsyms_num_syms = %08X, table_cnt = %d?" % (kallsyms_num_syms, table_cnt)
            ok = (kallsyms_num_syms & alignmask) == 0 and ((kallsyms_num_syms - table_cnt*ptrsize) & ~alignmask) == kallsyms_addresses
            if not ok:
                kallsyms_num_syms = (b - 1) & ~alignmask
                table_cnt = Dword(kallsyms_num_syms)
                print "kallsyms_num_syms = %08X, table_cnt = %d?" % (kallsyms_num_syms, table_cnt)
                ok = (kallsyms_num_syms & alignmask) == 0 and ((kallsyms_num_syms - table_cnt*ptrsize) & ~alignmask) == kallsyms_addresses
            if ok:
                print "%08X: found kallsyms_num_syms (%d)" % (kallsyms_num_syms, table_cnt)
                kallsyms_names = kallsyms_num_syms + alignmask + 1
                a = kallsyms_names
                for i in range(table_cnt):
                    a += Byte(a) + 1
                kallsyms_markers = (a + alignmask) & ~alignmask
                a = kallsyms_markers + ptrsize * ((table_cnt + 255) >> 8)
                kallsyms_token_table = (a + alignmask) & ~alignmask
                a = kallsyms_token_table
                for i in range(256):
                    l = idaapi.get_max_ascii_length(a, ASCSTR_C, idaapi.ALOPT_IGNHEADS)
                    a += l + 1
                kallsyms_token_index = (a + alignmask) & ~alignmask
                print "%08X: kallsyms_num_syms" % kallsyms_num_syms
                print "%08X: kallsyms_addresses" % kallsyms_addresses
                print "%08X: kallsyms_num_syms" % kallsyms_num_syms
                print "%08X: kallsyms_names" % kallsyms_names
                print "%08X: kallsyms_markers" % kallsyms_markers
                print "%08X: kallsyms_token_table" % kallsyms_token_table
                print "%08X: kallsyms_token_index" % kallsyms_token_index
                Jump(kallsyms_num_syms)
                if AskYN(0, "HIDECANCEL\nDiscovered %d symbols. Proceed with renaming?" % Dword(kallsyms_num_syms)) == 1:
                    MakeName(kallsyms_num_syms, "kallsyms_num_syms")
                    MakeName(kallsyms_addresses, "kallsyms_addresses")
                    MakeName(kallsyms_num_syms, "kallsyms_num_syms")
                    MakeName(kallsyms_names, "kallsyms_names")
                    MakeName(kallsyms_markers, "kallsyms_markers")
                    MakeName(kallsyms_token_table, "kallsyms_token_table")
                    MakeName(kallsyms_token_index, "kallsyms_token_index")
                else:
                    kallsyms_num_syms = BADADDR
                break

if kallsyms_num_syms != BADADDR:
    do_kallsyms(True, True)
else:
    # you will need to find the kallsyms_num_syms value in the kernel image
    # and all other tables mentioned below
    # consult kallsyms.c from the kernel sources
    # after that the script can parse the tables and create the symbols list
    Message("kallsyms tables not found!\n")
