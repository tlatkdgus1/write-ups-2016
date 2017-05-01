import angr

def main():
    p = angr.Project("baby-re", load_options={'auto_load_libs': False})
    p = p.factory.path_group(threads=4)
    p.explore(find=(0x402964, ), avoid=(0x402941,))

    return p.found[0].state.posix.dumps(1)
 
 
if __name__ == '__main__':
	print repr(main())
