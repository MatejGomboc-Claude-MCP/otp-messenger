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

# Source files
set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/cryptoengine.cpp
    src/codebook.cpp
    src/authentication.cpp
    src/messageprotocol.cpp
)

# Header files
set(HEADERS
    src/mainwindow.h
    src/cryptoengine.h
    src/codebook.h
    src/authentication.h
    src/messageprotocol.h
)

# UI files
set(UI_FILES
    src/mainwindow.ui
)

# Resource files
set(RESOURCE_FILES
    resources/resources.qrc
)

# Create executable
add_executable(OTPMessenger
    ${SOURCES}
    ${HEADERS}
    ${UI_FILES}
    ${RESOURCE_FILES}
)

# Link Qt libraries
target_link_libraries(OTPMessenger PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

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
