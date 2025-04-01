# UI Element Update Guide

This document provides guidance for updating the UI elements from the old naming convention (`CypherBook`) to the new standardized naming (`CodeBook`).

## Background

The OTP Messenger codebase has been refactored to remove redundant classes and standardize on `CodeBook` instead of `CypherBook`. While all C++ code has been updated, the UI elements in the `.ui` files still use the old naming convention. This guide describes the needed UI updates to complete the transition.

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
   - Any labels or other UI elements referring to "Cypher Book" should be updated to "Code Book"

4. **Line Edits**:
   - `lineEditCypherBook` → `lineEditCodeBook`

## How to Update the UI File

1. Open `src/mainwindow.ui` in Qt Designer
2. Locate each element in the Object Inspector panel
3. Right-click on each element and select "Change objectName..." to rename it
4. Also update any visible text properties (e.g., button text, label text) to reflect the new naming
5. Save the file and rebuild the project

## Compatibility Notes

Until the UI file is updated, the C++ code will continue to work with the existing UI elements. The code has been written to handle both naming conventions with appropriate comments to indicate where UI elements still use the old naming.

## Future Considerations

After updating the UI elements, it would be good practice to:

1. Check for any references to "CypherBook" in documentation
2. Update user guides or help text
3. Consider renaming file extensions in existing files from `.cypherbook` to `.codebook`

For now, the application supports both file extensions for backward compatibility.
