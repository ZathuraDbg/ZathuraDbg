EXE = Zathura 
IMGUI_DIR = ../vendor/imgui
SOURCES = main.cpp
EXTRA = ../vendor/ImGuiColorTextEdit
APP = ./app
UTILS = ./utils
TASKS = ./app/tasks
WINDOWS = ./app/windows
REGEX = ../vendor/ImGuiColorTextEdit/vendor/regex/include
MAP = ../vendor/ordered-map/include
DIALOGS = ./app/dialogs
LOGGING = ../vendor/log
INTEGRATION = ./app/integration
KEYSTONE = ../vendor/keystone
TINYFD_DIR = ../vendor/code
SOURCES += $(IMGUI_DIR)/imgui.cpp $(IMGUI_DIR)/imgui_draw.cpp $(IMGUI_DIR)/imgui_tables.cpp $(IMGUI_DIR)/imgui_widgets.cpp
SOURCES += $(IMGUI_DIR)/backends/imgui_impl_glfw.cpp $(IMGUI_DIR)/backends/imgui_impl_opengl3.cpp
SOURCES += $(IMGUI_DIR)/misc/cpp/imgui_stdlib.cpp
SOURCES += $(EXTRA)/TextEditor.h
SOURCES += $(EXTRA)/TextEditor.cpp
SOURCES += $(EXTRA)/LanguageDefinitions.cpp
#SOURCES += $(DIALOGS)/dialogHeader.hpp
SOURCES += $(DIALOGS)/fileDialogs.cpp
# SOURCES += $(EXTRA)/ImGuiDebugPanel.cpp
# SOURCES += $(EXTRA)/UnitTests.cpp
SOURCES += $(APP)/app.hpp
SOURCES += $(UTILS)/fonts.hpp
SOURCES += $(UTILS)/layoutmanager.h
SOURCES += $(TASKS)/fileTasks.hpp
SOURCES += $(TASKS)/editorTasks.hpp
SOURCES += $(WINDOWS)/registerWindow.cpp
SOURCES += $(WINDOWS)/consoleWindow.cpp
SOURCES += $(WINDOWS)/hexEditorWindow.cpp
SOURCES += $(WINDOWS)/stackWindow.cpp
SOURCES += $(APP)/buttons.cpp
SOURCES += $(WINDOWS)/menuBar.cpp
#SOURCES += $(LOGGING)/clue.hpp
#SOURCES += $(APP)/stackEditorWindow.cpp
SOURCES += $(INTEGRATION)/interpreter/interpreter.hpp
SOURCES += $(INTEGRATION)/interpreter/interpreter.cpp
#SOURCES += $(INTEGRATION)/utils/hex/hex.hpp
SOURCES += $(INTEGRATION)/keystone/assembler.hpp
SOURCES += $(INTEGRATION)/keystone/assembler.cpp
SOURCES += $(TINYFD_DIR)/tinyfiledialogs.h
SOURCES += $(APP)/arch/x86.hpp
SOURCES += $(APP)/arch/x86.cpp

OBJS = $(addsuffix .o, $(basename $(notdir $(SOURCES))))
UNAME_S := $(shell uname -s)
LINUX_GL_LIBS = -lGL

CXXFLAGS = -std=c++17 -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends -I$(REGEX) -I$(MAP) -I$(DIALOGS) -I$(TASKS) -I$(WINDOWS) 
CXXFLAGS += -g  -Wformat
CXXFLAGS += -L../vendor/unicorn/include -lunicorn
CXXFLAGS += -L../vendor/keystone -l:libkeystone.a -L../vendor/keystone/include 
CXXFLAGS += -DLOG_TO_FILE=\".Zathura.zlog\"
# CXXFLAGS += -DLOG_TO_STRING
LIBS =

ifeq ($(UNAME_S), Linux) #LINUX
	ECHO_MESSAGE = "Linux"
	LIBS += $(LINUX_GL_LIBS) `pkg-config --static --libs glfw3`

	CXXFLAGS += `pkg-config --cflags glfw3`
	CFLAGS = $(CXXFLAGS)
endif

ifeq ($(UNAME_S), Darwin) #APPLE
	ECHO_MESSAGE = "Mac OS X"
	LIBS += -framework OpenGL -framework Cocoa -framework IOKit -framework CoreVideo
	LIBS += -L/usr/local/lib -L/opt/local/lib -L/opt/homebrew/lib
	#LIBS += -lglfw3
	LIBS += -lglfw

	CXXFLAGS += -I/usr/local/include -I/opt/local/include -I/opt/homebrew/include
	CFLAGS = $(CXXFLAGS)
endif


ifeq ($(OS), Windows_NT)
	ECHO_MESSAGE = "MinGW"
	LIBS += -lglfw3 -lgdi32 -lopengl32 -limm32

	CXXFLAGS += `pkg-config --cflags glfw3`
	CFLAGS = $(CXXFLAGS)
endif
##---------------------------------------------------------------------
## BUILD RULES
##---------------------------------------------------------------------

%.o:%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(IMGUI_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(IMGUI_DIR)/backends/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(EXTRA)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(APP)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(UTILS)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(DIALOGS)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(TASKS)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(WINDOWS)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<


%.o:$(INTEGRATION)/interpreter/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(INTEGRATION)/keystone/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(TINYFD_DIR)/%.c
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(IMGUI_DIR)/misc/cpp/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o:$(APP)/arch/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

#%.o:$(INTEGRATION)/utils/hex/%.cpp
#	$(CXX) $(CXXFLAGS) -c -o $@ $<

all: $(EXE)
	@echo Build complete for $(ECHO_MESSAGE)

$(EXE): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LIBS)

run: $(EXE)
	./Zathura

clean:
	rm -f Zathura app.o main.o

c:
	rm -rf Zathura app.o main.o

