##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=ex4_to_mq4_auto
ConfigurationName      :=Debug
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
WorkspacePath          := "D:\prj\cl workspace"
ProjectPath            := "D:\prj\cl workspace\ex4_to_mq4_auto"
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=s0ck3t
Date                   :=2013-01-18
CodeLitePath           :="d:\CodeLite"
LinkerName             :=gcc
ArchiveTool            :=ar rcus
SharedObjectLinkerName :=gcc -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.o.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
CompilerName           :=gcc
C_CompilerName         :=gcc
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E 
ObjectsFileList        :="D:\prj\cl workspace\ex4_to_mq4_auto\ex4_to_mq4_auto.txt"
PCHCompileFlags        :=
MakeDirCommand         :=makedir
CmpOptions             := -ggdb -Wl,-pie -g $(Preprocessors)
C_CmpOptions           := -ggdb -Wl,-pie -g $(Preprocessors)
LinkOptions            :=  -ggdb -Wl,-pie -g
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). 
IncludePCH             := 
RcIncludePath          := 
Libs                   := $(LibrarySwitch)shell32 $(LibrarySwitch)ole32 $(LibrarySwitch)uuid $(LibrarySwitch)psapi 
ArLibs                 :=  "shell32" "ole32" "uuid" "psapi" 
LibPath                := $(LibraryPathSwitch). 


##
## User defined environment variables
##
CodeLiteDir:=d:\CodeLite
UNIT_TEST_PP_SRC_DIR:=e:\UnitTest++-1.3
WXWIN:=e:\wxWidgets-2.8.12
PATH:=$(WXWIN)\lib\gcc_dll;$(PATH)
WXCFG:=gcc_dll\mswu
Objects=$(IntermediateDirectory)/scit_scit$(ObjectSuffix) $(IntermediateDirectory)/libdasm_libdasm$(ObjectSuffix) $(IntermediateDirectory)/ex4_to_mq4_auto$(ObjectSuffix) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild
all: $(OutputFile)

$(OutputFile): $(IntermediateDirectory)/.d $(Objects) 
	@$(MakeDirCommand) $(@D)
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects) > $(ObjectsFileList)
	$(LinkerName) $(OutputSwitch)$(OutputFile) @$(ObjectsFileList) $(LibPath) $(Libs) $(LinkOptions)

$(IntermediateDirectory)/.d:
	@$(MakeDirCommand) "./Debug"

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/scit_scit$(ObjectSuffix): scit/scit.c $(IntermediateDirectory)/scit_scit$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "D:/prj/cl workspace/ex4_to_mq4_auto/scit/scit.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/scit_scit$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/scit_scit$(DependSuffix): scit/scit.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/scit_scit$(ObjectSuffix) -MF$(IntermediateDirectory)/scit_scit$(DependSuffix) -MM "D:/prj/cl workspace/ex4_to_mq4_auto/scit/scit.c"

$(IntermediateDirectory)/scit_scit$(PreprocessSuffix): scit/scit.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/scit_scit$(PreprocessSuffix) "D:/prj/cl workspace/ex4_to_mq4_auto/scit/scit.c"

$(IntermediateDirectory)/libdasm_libdasm$(ObjectSuffix): scit/libdasm/libdasm.c $(IntermediateDirectory)/libdasm_libdasm$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "D:/prj/cl workspace/ex4_to_mq4_auto/scit/libdasm/libdasm.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/libdasm_libdasm$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/libdasm_libdasm$(DependSuffix): scit/libdasm/libdasm.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/libdasm_libdasm$(ObjectSuffix) -MF$(IntermediateDirectory)/libdasm_libdasm$(DependSuffix) -MM "D:/prj/cl workspace/ex4_to_mq4_auto/scit/libdasm/libdasm.c"

$(IntermediateDirectory)/libdasm_libdasm$(PreprocessSuffix): scit/libdasm/libdasm.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/libdasm_libdasm$(PreprocessSuffix) "D:/prj/cl workspace/ex4_to_mq4_auto/scit/libdasm/libdasm.c"

$(IntermediateDirectory)/ex4_to_mq4_auto$(ObjectSuffix): ex4_to_mq4_auto.c $(IntermediateDirectory)/ex4_to_mq4_auto$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "D:/prj/cl workspace/ex4_to_mq4_auto/ex4_to_mq4_auto.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/ex4_to_mq4_auto$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/ex4_to_mq4_auto$(DependSuffix): ex4_to_mq4_auto.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/ex4_to_mq4_auto$(ObjectSuffix) -MF$(IntermediateDirectory)/ex4_to_mq4_auto$(DependSuffix) -MM "D:/prj/cl workspace/ex4_to_mq4_auto/ex4_to_mq4_auto.c"

$(IntermediateDirectory)/ex4_to_mq4_auto$(PreprocessSuffix): ex4_to_mq4_auto.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/ex4_to_mq4_auto$(PreprocessSuffix) "D:/prj/cl workspace/ex4_to_mq4_auto/ex4_to_mq4_auto.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) $(IntermediateDirectory)/scit_scit$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/scit_scit$(DependSuffix)
	$(RM) $(IntermediateDirectory)/scit_scit$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/libdasm_libdasm$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/libdasm_libdasm$(DependSuffix)
	$(RM) $(IntermediateDirectory)/libdasm_libdasm$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/ex4_to_mq4_auto$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/ex4_to_mq4_auto$(DependSuffix)
	$(RM) $(IntermediateDirectory)/ex4_to_mq4_auto$(PreprocessSuffix)
	$(RM) $(OutputFile)
	$(RM) $(OutputFile).exe
	$(RM) "D:\prj\cl workspace\.build-debug\ex4_to_mq4_auto"


