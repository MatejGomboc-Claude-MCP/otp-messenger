cmake_minimum_required(VERSION 3.16)
project(OTPMessenger VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Add source files
set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/mainwindow.ui
    
    # New secure implementation
    src/secure_memory.cpp
    src/secure_memory.h
    src/secure_wiper.cpp
    src/secure_wiper.h
    src/pad_file_manager.cpp
    src/pad_file_manager.h
    src/message_protocol.cpp
    src/message_protocol.h
    
    # Authentication system
    src/authentication.cpp
    src/authentication.h
)

# Add resource files
set(RESOURCES
    resources/resources.qrc
)

# Create the executable
add_executable(OTPMessenger 
    ${SOURCES}
    ${RESOURCES}
)

# Link Qt libraries
target_link_libraries(OTPMessenger PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    bcrypt
)

# Install rules
install(TARGETS OTPMessenger DESTINATION bin)
