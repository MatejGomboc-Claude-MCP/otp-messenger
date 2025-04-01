# UI Element Update Guide

This document provides guidance for updating the UI elements to align with the CodeBook naming convention adopted in the codebase.

## Background

The OTP Messenger codebase uses the `CodeBook` class for managing encryption key material. However, the UI elements in the `.ui` files currently use outdated naming. This guide describes the UI updates needed to align the UI with the code.

## Required UI Changes

The following UI elements in `src/mainwindow.ui` should be renamed:

1. **Menu Actions**:
   - `actionNew_Cypher_Book` → `actionNew_Code_Book`
   - `actionOpen_Cypher_Book` → `actionOpen_Code_Book`
   - `actionSave_Cypher_Book` → `actionSave_Code_Book`

2. **Buttons**:
   - `pushButtonOpenCypherBook` → `pushButtonOpenCodeBook`
   - `pushButtonNewCypherBook` → `pushButtonNewCodeBook`

3. **Labels**:
   - Any labels referring to "Cypher Book" should be updated to "Code Book"

4. **Line Edits**:
   - `lineEditCypherBook` → `lineEditCodeBook`

5. **Tab Titles**:
   - Any tab titles referring to "Cypher Book" should be updated to "Code Book"

6. **Dialog Titles**:
   - All dialog titles should be updated to use "Codebook" consistently

## How to Update the UI File

1. Open `src/mainwindow.ui` in Qt Designer
2. Locate each element in the Object Inspector panel
3. Right-click on each element and select "Change objectName..." to rename it
4. Also update any visible text properties (e.g., button text, label text)
5. Save the file and rebuild the project

## Implementation Note

Until the UI elements are renamed, the C++ code contains the necessary connections to work with the current UI element names, with comments indicating where names need to be updated.
