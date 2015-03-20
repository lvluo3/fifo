src_file1 = Glob('./*.c')
src_file2 = Glob('../err_handle/*.c')
src_file3 = Glob('../udpserver/*.c')
src_file4 = Glob('../wrap_base/*.c')
src_file5 = Glob('../data_structure/hash_al/*.c')

src_file = src_file1 + src_file2 + src_file3 + src_file4 +src_file5

Program('run' , src_file1 , CPPPATH = ['.'] , CC = ['gcc'],
CFLAGS = ['-g'] , LINKFLAGS = ['-g' , '-rdynamic'] , LIBS = ['rt']
#LIBS = ['g729a'] , LIBPATH = ['.']
# LDFLAG = ['-g']
)
#SharedLibrary('so' , 'so1.c')
#StaticLibrary('so','so1.c')
