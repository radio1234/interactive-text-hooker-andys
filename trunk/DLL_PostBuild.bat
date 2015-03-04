cd %1
echo %1
move Release\%2.lib libs\
move Release\%2.exp libs\
echo Release\IHF_EnableSEH Release\%2.dll
Release\IHF_EnableSEH Release\%2.dll
del Release\*.pdb
del Release\IHF_EnableSEH.*