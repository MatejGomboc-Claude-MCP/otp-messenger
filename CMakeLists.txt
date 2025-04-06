cmake_minimum_required(VERSION 3.16)

project(OTPMessenger VERSION 1.0 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/mainwindow.ui
    src/secure_memory.cpp
    src/secure_memory.h
    src/secure_wiper.cpp
    src/secure_wiper.h
    src/pad_file_manager.cpp
    src/pad_file_manager.h
    src/message_protocol.cpp
    src/message_protocol.h
)

qt6_add_resources(RESOURCES resources/resources.qrc)

# Add the executable
add_executable(OTPMessenger
    ${SOURCES}
    ${RESOURCES}
)

# Link libraries
target_link_libraries(OTPMessenger PRIVATE
    Qt6::Widgets
    bcrypt.lib
)

# Installation
install(TARGETS OTPMessenger
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Set application properties
set_target_properties(OTPMessenger PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER com.example.OTPMessenger
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(OTPMessenger)
endif()
