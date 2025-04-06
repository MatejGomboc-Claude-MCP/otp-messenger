cmake_minimum_required(VERSION 3.16)

project(OTPMessenger VERSION 0.1 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt packages
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# Enable automatic handling of moc, uic, and rcc
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Source files for the core security components
set(CORE_SOURCES
    src/secure_memory.cpp
    src/secure_wiper.cpp
    src/pad_file_manager.cpp
    src/message_protocol.cpp
)

# Header files for the core security components
set(CORE_HEADERS
    src/secure_memory.h
    src/secure_wiper.h
    src/pad_file_manager.h
    src/message_protocol.h
)

# Source files for the UI/app components
set(UI_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/authentication.cpp
)

# Header files for the UI/app components
set(UI_HEADERS
    src/mainwindow.h
    src/authentication.h
)

# UI files
set(UI_FILES
    src/mainwindow.ui
)

# Resource files
set(RESOURCE_FILES
    resources/resources.qrc
)

# Combine all sources
set(ALL_SOURCES
    ${CORE_SOURCES}
    ${CORE_HEADERS}
    ${UI_SOURCES}
    ${UI_HEADERS}
    ${UI_FILES}
    ${RESOURCE_FILES}
)

# Create executable
add_executable(OTPMessenger
    ${ALL_SOURCES}
)

# Link Qt libraries
target_link_libraries(OTPMessenger PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

# Link Windows-specific libraries
if(WIN32)
    target_link_libraries(OTPMessenger PRIVATE
        bcrypt.lib    # For cryptography
        advapi32.lib  # For Windows security APIs
    )
endif()

# Installation
install(TARGETS OTPMessenger
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# For macOS bundle
if(APPLE)
    set_target_properties(OTPMessenger PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/MacOSXBundleInfo.plist.in
    )
endif(APPLE)

# For Windows RC file (icon, etc.)
if(WIN32)
    target_sources(OTPMessenger PRIVATE src/otpmessenger.rc)
endif()
