# Java test code coverage

**76.8% line coverage** — 22,865 covered / 29,780 total production Java lines.

Source: [f8ee3b7a83bbf857faa8aae43c61669537f3e4bb](https://github.com/zwilcox/GhidraDwarfForge/commit/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb). [CI run and downloadable JaCoCo HTML report](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43566698124).

This measures Java code exercised by the instrumented `JavaExec` tests in the Linux extension-build job. All compiled `src/main/java` classes are in the denominator, including unexecuted classes. It is separate from exported source/type/variable evidence coverage.

Native C/libdwarf, Python/shell tests, Ghidra scripts, external libraries, and independently launched headless/integration JVMs are not instrumented. Their Java entry points remain in the denominator when they belong to `src/main/java`. JaCoCo applies its standard generated-bytecode filters. The published report branch holds the last fully validated main result; artifacts from other runs are provisional measurements.

JaCoCo 0.8.16; XML SHA-256: `06e9d1bba6778d079f4177ea25df5df0fcb823ab4681a2d14f4e6ed997742c81`.

## Measured source files

| Source | Covered | Missed | Line coverage |
| --- | ---: | ---: | ---: |
| [ghidradwarfforge/AddressNormalizer.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/AddressNormalizer.java) | 2 | 0 | 100.0% |
| [ghidradwarfforge/CallMemoryEffects.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/CallMemoryEffects.java) | 133 | 3 | 97.8% |
| [ghidradwarfforge/CompositeValueFlow.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/CompositeValueFlow.java) | 84 | 3 | 96.6% |
| [ghidradwarfforge/DirectLeafCalls.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/DirectLeafCalls.java) | 126 | 0 | 100.0% |
| [ghidradwarfforge/ExporterPreflight.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/ExporterPreflight.java) | 0 | 10 | 0.0% |
| [ghidradwarfforge/GhidraAllocationDecompiler.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraAllocationDecompiler.java) | 60 | 79 | 43.2% |
| [ghidradwarfforge/GhidraAnnotationInventory.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraAnnotationInventory.java) | 0 | 109 | 0.0% |
| [ghidradwarfforge/GhidraArm32FunctionModes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraArm32FunctionModes.java) | 175 | 8 | 95.6% |
| [ghidradwarfforge/GhidraArm32SectionModes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraArm32SectionModes.java) | 106 | 6 | 94.6% |
| [ghidradwarfforge/GhidraCallParameters.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraCallParameters.java) | 139 | 5 | 96.5% |
| [ghidradwarfforge/GhidraClassBindings.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraClassBindings.java) | 82 | 3 | 96.5% |
| [ghidradwarfforge/GhidraClassScopes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraClassScopes.java) | 127 | 8 | 94.1% |
| [ghidradwarfforge/GhidraCompilerCallPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraCompilerCallPolicy.java) | 13 | 4 | 76.5% |
| [ghidradwarfforge/GhidraCortexM3Profile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraCortexM3Profile.java) | 24 | 0 | 100.0% |
| [ghidradwarfforge/GhidraCustomCallStorage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraCustomCallStorage.java) | 40 | 8 | 83.3% |
| [ghidradwarfforge/GhidraCxxProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraCxxProfile.java) | 126 | 34 | 78.8% |
| [ghidradwarfforge/GhidraDeclarationBindings.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraDeclarationBindings.java) | 67 | 1 | 98.5% |
| [ghidradwarfforge/GhidraEncoderTree.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraEncoderTree.java) | 70 | 2 | 97.2% |
| [ghidradwarfforge/GhidraEquateEvidence.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraEquateEvidence.java) | 0 | 122 | 0.0% |
| [ghidradwarfforge/GhidraEquateNames.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraEquateNames.java) | 0 | 25 | 0.0% |
| [ghidradwarfforge/GhidraEquateSource.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraEquateSource.java) | 0 | 49 | 0.0% |
| [ghidradwarfforge/GhidraExportConsistency.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraExportConsistency.java) | 26 | 1 | 96.3% |
| [ghidradwarfforge/GhidraFunctionAliases.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraFunctionAliases.java) | 102 | 8 | 92.7% |
| [ghidradwarfforge/GhidraFunctionRelations.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraFunctionRelations.java) | 38 | 7 | 84.4% |
| [ghidradwarfforge/GhidraFunctionSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraFunctionSymbols.java) | 72 | 27 | 72.7% |
| [ghidradwarfforge/GhidraImageBase.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraImageBase.java) | 7 | 0 | 100.0% |
| [ghidradwarfforge/GhidraInheritanceBindings.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraInheritanceBindings.java) | 229 | 4 | 98.3% |
| [ghidradwarfforge/GhidraInstructionContext.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraInstructionContext.java) | 0 | 184 | 0.0% |
| [ghidradwarfforge/GhidraInstructionEvidence.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraInstructionEvidence.java) | 61 | 8 | 88.4% |
| [ghidradwarfforge/GhidraLexicalScopes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraLexicalScopes.java) | 211 | 10 | 95.5% |
| [ghidradwarfforge/GhidraListingAnnotationSource.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraListingAnnotationSource.java) | 0 | 65 | 0.0% |
| [ghidradwarfforge/GhidraLocalMappings.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraLocalMappings.java) | 129 | 13 | 90.8% |
| [ghidradwarfforge/GhidraMmioProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraMmioProfile.java) | 55 | 37 | 59.8% |
| [ghidradwarfforge/GhidraParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraParameterAllocation.java) | 15 | 1 | 93.8% |
| [ghidradwarfforge/GhidraProjectOutputProtection.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraProjectOutputProtection.java) | 0 | 31 | 0.0% |
| [ghidradwarfforge/GhidraSourceContext.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraSourceContext.java) | 0 | 181 | 0.0% |
| [ghidradwarfforge/GhidraStaticBindings.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraStaticBindings.java) | 130 | 8 | 94.2% |
| [ghidradwarfforge/GhidraStaticRecovery.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraStaticRecovery.java) | 41 | 46 | 47.1% |
| [ghidradwarfforge/GhidraSyntheticSource.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraSyntheticSource.java) | 71 | 84 | 45.8% |
| [ghidradwarfforge/GhidraTargetAgreement.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraTargetAgreement.java) | 26 | 0 | 100.0% |
| [ghidradwarfforge/GhidraTypeGraph.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraTypeGraph.java) | 605 | 60 | 91.0% |
| [ghidradwarfforge/GhidraVariableStorage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraVariableStorage.java) | 817 | 50 | 94.2% |
| [ghidradwarfforge/GhidraVtableBindings.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/GhidraVtableBindings.java) | 211 | 31 | 87.2% |
| [ghidradwarfforge/IntraInstructionFlow.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/IntraInstructionFlow.java) | 39 | 0 | 100.0% |
| [ghidradwarfforge/MergedLocalLifetime.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/MergedLocalLifetime.java) | 162 | 1 | 99.4% |
| [ghidradwarfforge/RegisterByteSlice.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/RegisterByteSlice.java) | 36 | 0 | 100.0% |
| [ghidradwarfforge/RegisterCopyLifetime.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/RegisterCopyLifetime.java) | 138 | 2 | 98.6% |
| [ghidradwarfforge/RegisterDefinitionFlow.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/RegisterDefinitionFlow.java) | 162 | 10 | 94.2% |
| [ghidradwarfforge/StackLocalLifetime.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/StackLocalLifetime.java) | 38 | 0 | 100.0% |
| [ghidradwarfforge/StackSpillLifetime.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/StackSpillLifetime.java) | 125 | 6 | 95.4% |
| [ghidradwarfforge/StackValueFlow.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/StackValueFlow.java) | 525 | 17 | 96.9% |
| [ghidradwarfforge/TruncatedStackDepth.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/TruncatedStackDepth.java) | 72 | 4 | 94.7% |
| [ghidradwarfforge/annotations/EquateCatalog.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/annotations/EquateCatalog.java) | 0 | 106 | 0.0% |
| [ghidradwarfforge/annotations/SyntheticConstant.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/annotations/SyntheticConstant.java) | 0 | 9 | 0.0% |
| [ghidradwarfforge/annotations/SyntheticConstants.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/annotations/SyntheticConstants.java) | 4 | 0 | 100.0% |
| [ghidradwarfforge/calls/CallSitePlan.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/CallSitePlan.java) | 51 | 9 | 85.0% |
| [ghidradwarfforge/calls/CallValue.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/CallValue.java) | 144 | 8 | 94.7% |
| [ghidradwarfforge/calls/GhidraBoundedSwitch.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/GhidraBoundedSwitch.java) | 208 | 9 | 95.9% |
| [ghidradwarfforge/calls/GhidraCallArgumentFlow.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/GhidraCallArgumentFlow.java) | 193 | 7 | 96.5% |
| [ghidradwarfforge/calls/GhidraCallSiteEvidence.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/GhidraCallSiteEvidence.java) | 178 | 6 | 96.7% |
| [ghidradwarfforge/calls/GhidraCallSitePlan.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/GhidraCallSitePlan.java) | 101 | 5 | 95.3% |
| [ghidradwarfforge/calls/GhidraTailStateProof.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/calls/GhidraTailStateProof.java) | 171 | 1 | 99.4% |
| [ghidradwarfforge/coverage/DecodedInstructions.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/DecodedInstructions.java) | 15 | 3 | 83.3% |
| [ghidradwarfforge/coverage/ExportCoverage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/ExportCoverage.java) | 70 | 4 | 94.6% |
| [ghidradwarfforge/coverage/ExportEmission.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/ExportEmission.java) | 37 | 3 | 92.5% |
| [ghidradwarfforge/coverage/LocationCoverage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/LocationCoverage.java) | 76 | 2 | 97.4% |
| [ghidradwarfforge/coverage/SourceCoverage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/SourceCoverage.java) | 5 | 0 | 100.0% |
| [ghidradwarfforge/coverage/SourceCoverageIndex.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/SourceCoverageIndex.java) | 78 | 4 | 95.1% |
| [ghidradwarfforge/coverage/SourceCoverageInventory.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/SourceCoverageInventory.java) | 105 | 3 | 97.2% |
| [ghidradwarfforge/coverage/TypeCoverage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/TypeCoverage.java) | 6 | 0 | 100.0% |
| [ghidradwarfforge/coverage/TypeCoverageIndex.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/TypeCoverageIndex.java) | 129 | 0 | 100.0% |
| [ghidradwarfforge/coverage/TypeGraphEvidence.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/TypeGraphEvidence.java) | 131 | 4 | 97.0% |
| [ghidradwarfforge/coverage/VariableCoverageInventory.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/VariableCoverageInventory.java) | 169 | 4 | 97.7% |
| [ghidradwarfforge/coverage/VariableCoverageTotals.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/coverage/VariableCoverageTotals.java) | 39 | 2 | 95.1% |
| [ghidradwarfforge/dwarf/Dwarf32InfoRepair.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/Dwarf32InfoRepair.java) | 112 | 57 | 66.3% |
| [ghidradwarfforge/dwarf/Dwarf5LineTable.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/Dwarf5LineTable.java) | 164 | 5 | 97.0% |
| [ghidradwarfforge/dwarf/Dwarf5LocationLists.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/Dwarf5LocationLists.java) | 111 | 11 | 91.0% |
| [ghidradwarfforge/dwarf/Dwarf5RangeLists.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/Dwarf5RangeLists.java) | 92 | 3 | 96.8% |
| [ghidradwarfforge/dwarf/DwarfAddressRanges.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/DwarfAddressRanges.java) | 34 | 1 | 97.1% |
| [ghidradwarfforge/dwarf/DwarfDebugFrame.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/DwarfDebugFrame.java) | 166 | 7 | 96.0% |
| [ghidradwarfforge/dwarf/DwarfInheritanceExpression.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/DwarfInheritanceExpression.java) | 0 | 28 | 0.0% |
| [ghidradwarfforge/dwarf/DwarfLocationExpression.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/DwarfLocationExpression.java) | 66 | 6 | 91.7% |
| [ghidradwarfforge/dwarf/SyntheticSourceRelocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/dwarf/SyntheticSourceRelocation.java) | 0 | 182 | 0.0% |
| [ghidradwarfforge/elf/Arm32CallAbi.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/Arm32CallAbi.java) | 100 | 3 | 97.1% |
| [ghidradwarfforge/elf/Arm32CallPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/Arm32CallPolicy.java) | 138 | 0 | 100.0% |
| [ghidradwarfforge/elf/Arm32FunctionAliasSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/Arm32FunctionAliasSymbols.java) | 160 | 7 | 95.8% |
| [ghidradwarfforge/elf/Arm32ModeSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/Arm32ModeSymbols.java) | 235 | 19 | 92.5% |
| [ghidradwarfforge/elf/Arm32SectionModes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/Arm32SectionModes.java) | 121 | 11 | 91.7% |
| [ghidradwarfforge/elf/Arm32SymbolValues.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/Arm32SymbolValues.java) | 4 | 0 | 100.0% |
| [ghidradwarfforge/elf/CallOriginSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/CallOriginSymbols.java) | 82 | 5 | 94.3% |
| [ghidradwarfforge/elf/CortexM3Profile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/CortexM3Profile.java) | 20 | 0 | 100.0% |
| [ghidradwarfforge/elf/DebugSectionCompression.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/DebugSectionCompression.java) | 50 | 2 | 96.2% |
| [ghidradwarfforge/elf/DebuglinkCandidateContent.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/DebuglinkCandidateContent.java) | 250 | 11 | 95.8% |
| [ghidradwarfforge/elf/DynamicSymbolMirror.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/DynamicSymbolMirror.java) | 212 | 4 | 98.1% |
| [ghidradwarfforge/elf/ElfBuildId.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfBuildId.java) | 150 | 6 | 96.2% |
| [ghidradwarfforge/elf/ElfCodeBytes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfCodeBytes.java) | 94 | 1 | 98.9% |
| [ghidradwarfforge/elf/ElfFunctionAlias.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfFunctionAlias.java) | 31 | 2 | 93.9% |
| [ghidradwarfforge/elf/ElfFunctionModeCue.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfFunctionModeCue.java) | 6 | 0 | 100.0% |
| [ghidradwarfforge/elf/ElfImage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfImage.java) | 266 | 5 | 98.2% |
| [ghidradwarfforge/elf/ElfLoadAllocations.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfLoadAllocations.java) | 25 | 0 | 100.0% |
| [ghidradwarfforge/elf/ElfLocalFunctionSymbol.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfLocalFunctionSymbol.java) | 6 | 0 | 100.0% |
| [ghidradwarfforge/elf/ElfLocalMappingSymbol.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfLocalMappingSymbol.java) | 6 | 1 | 85.7% |
| [ghidradwarfforge/elf/ElfLocalObjectSymbol.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfLocalObjectSymbol.java) | 4 | 1 | 80.0% |
| [ghidradwarfforge/elf/ElfLocalSymbol.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfLocalSymbol.java) | 0 | 0 | not applicable |
| [ghidradwarfforge/elf/ElfNoteFormats.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfNoteFormats.java) | 4 | 0 | 100.0% |
| [ghidradwarfforge/elf/ElfRelocatedPointers.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfRelocatedPointers.java) | 62 | 2 | 96.9% |
| [ghidradwarfforge/elf/ElfRelocationEffects.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfRelocationEffects.java) | 156 | 1 | 99.4% |
| [ghidradwarfforge/elf/ElfRuntimeRelocations.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ElfRuntimeRelocations.java) | 163 | 3 | 98.2% |
| [ghidradwarfforge/elf/EquateNameReservations.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/EquateNameReservations.java) | 34 | 39 | 46.6% |
| [ghidradwarfforge/elf/ExecutableProgramBytes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/ExecutableProgramBytes.java) | 248 | 12 | 95.4% |
| [ghidradwarfforge/elf/FunctionAliasSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/FunctionAliasSymbols.java) | 179 | 5 | 97.3% |
| [ghidradwarfforge/elf/GdbCompanion.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/GdbCompanion.java) | 0 | 153 | 0.0% |
| [ghidradwarfforge/elf/InheritedFrameBytes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/InheritedFrameBytes.java) | 28 | 4 | 87.5% |
| [ghidradwarfforge/elf/MatchedElfAllocations.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MatchedElfAllocations.java) | 367 | 22 | 94.3% |
| [ghidradwarfforge/elf/MatchedElfPrefix.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MatchedElfPrefix.java) | 125 | 7 | 94.7% |
| [ghidradwarfforge/elf/MatchedElfSidecarWriter.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MatchedElfSidecarWriter.java) | 537 | 46 | 92.1% |
| [ghidradwarfforge/elf/MipsAbiFlags.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MipsAbiFlags.java) | 63 | 1 | 98.4% |
| [ghidradwarfforge/elf/MipsAggregateCallPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MipsAggregateCallPolicy.java) | 102 | 0 | 100.0% |
| [ghidradwarfforge/elf/MipsDynamicSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MipsDynamicSymbols.java) | 1 | 0 | 100.0% |
| [ghidradwarfforge/elf/MipsFloatingCallPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MipsFloatingCallPolicy.java) | 83 | 0 | 100.0% |
| [ghidradwarfforge/elf/MipsFunctionAliasSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MipsFunctionAliasSymbols.java) | 62 | 2 | 96.9% |
| [ghidradwarfforge/elf/MipsWideCallPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/MipsWideCallPolicy.java) | 136 | 1 | 99.3% |
| [ghidradwarfforge/elf/OriginalFrameSources.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/OriginalFrameSources.java) | 131 | 24 | 84.5% |
| [ghidradwarfforge/elf/OriginalFrameView.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/OriginalFrameView.java) | 55 | 1 | 98.2% |
| [ghidradwarfforge/elf/OriginalUnwindCoverage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/OriginalUnwindCoverage.java) | 45 | 4 | 91.8% |
| [ghidradwarfforge/elf/OwnedDebuglinkCandidate.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/OwnedDebuglinkCandidate.java) | 221 | 6 | 97.4% |
| [ghidradwarfforge/elf/SectionlessDynamicSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/SectionlessDynamicSymbols.java) | 287 | 9 | 97.0% |
| [ghidradwarfforge/elf/SectionlessUnwind.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/SectionlessUnwind.java) | 163 | 3 | 98.2% |
| [ghidradwarfforge/elf/SyntheticSourceSidecar.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/SyntheticSourceSidecar.java) | 0 | 200 | 0.0% |
| [ghidradwarfforge/elf/VtableSymbols.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/elf/VtableSymbols.java) | 88 | 8 | 91.7% |
| [ghidradwarfforge/firmware/FirmwareExportImage.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/firmware/FirmwareExportImage.java) | 0 | 162 | 0.0% |
| [ghidradwarfforge/firmware/FirmwareMemoryMap.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/firmware/FirmwareMemoryMap.java) | 74 | 2 | 97.4% |
| [ghidradwarfforge/firmware/FirmwareTarget.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/firmware/FirmwareTarget.java) | 16 | 7 | 69.6% |
| [ghidradwarfforge/firmware/GhidraFirmwareMemoryMap.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/firmware/GhidraFirmwareMemoryMap.java) | 94 | 6 | 94.0% |
| [ghidradwarfforge/firmware/GhidraFirmwareSession.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/firmware/GhidraFirmwareSession.java) | 0 | 117 | 0.0% |
| [ghidradwarfforge/formatters/FormatterPlan.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/formatters/FormatterPlan.java) | 72 | 7 | 91.1% |
| [ghidradwarfforge/locations/TargetRegisterMap.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/locations/TargetRegisterMap.java) | 156 | 9 | 94.5% |
| [ghidradwarfforge/locations/VariableStorageModel.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/locations/VariableStorageModel.java) | 90 | 13 | 87.4% |
| [ghidradwarfforge/nativeapi/Arm32EndianProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/Arm32EndianProfile.java) | 12 | 0 | 100.0% |
| [ghidradwarfforge/nativeapi/DwarfConstants.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/DwarfConstants.java) | 0 | 0 | not applicable |
| [ghidradwarfforge/nativeapi/DwarfNativeTypes.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/DwarfNativeTypes.java) | 0 | 16 | 0.0% |
| [ghidradwarfforge/nativeapi/DwarfTarget.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/DwarfTarget.java) | 82 | 12 | 87.2% |
| [ghidradwarfforge/nativeapi/LibDwarfConsumer.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/LibDwarfConsumer.java) | 0 | 0 | not applicable |
| [ghidradwarfforge/nativeapi/LibDwarfProducer.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/LibDwarfProducer.java) | 0 | 0 | not applicable |
| [ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java) | 97 | 1099 | 8.1% |
| [ghidradwarfforge/nativeapi/PackagedNativeLibraries.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/nativeapi/PackagedNativeLibraries.java) | 53 | 14 | 79.1% |
| [ghidradwarfforge/output/ArtifactPairPublisher.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ArtifactPairPublisher.java) | 136 | 9 | 93.8% |
| [ghidradwarfforge/output/ArtifactValidationBinding.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ArtifactValidationBinding.java) | 0 | 53 | 0.0% |
| [ghidradwarfforge/output/AttachmentCancellationFile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentCancellationFile.java) | 17 | 2 | 89.5% |
| [ghidradwarfforge/output/AttachmentExportBinding.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentExportBinding.java) | 60 | 14 | 81.1% |
| [ghidradwarfforge/output/AttachmentFileStore.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentFileStore.java) | 122 | 10 | 92.4% |
| [ghidradwarfforge/output/AttachmentGui.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentGui.java) | 34 | 194 | 14.9% |
| [ghidradwarfforge/output/AttachmentHelper.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentHelper.java) | 139 | 131 | 51.5% |
| [ghidradwarfforge/output/AttachmentInvocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentInvocation.java) | 106 | 3 | 97.2% |
| [ghidradwarfforge/output/AttachmentOperation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentOperation.java) | 162 | 13 | 92.6% |
| [ghidradwarfforge/output/AttachmentPathArgument.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentPathArgument.java) | 21 | 0 | 100.0% |
| [ghidradwarfforge/output/AttachmentPaths.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentPaths.java) | 61 | 6 | 91.0% |
| [ghidradwarfforge/output/AttachmentPreparation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentPreparation.java) | 71 | 2 | 97.3% |
| [ghidradwarfforge/output/AttachmentReceipt.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentReceipt.java) | 205 | 20 | 91.1% |
| [ghidradwarfforge/output/AttachmentReceiptStore.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentReceiptStore.java) | 128 | 14 | 90.1% |
| [ghidradwarfforge/output/AttachmentRecoveryFile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentRecoveryFile.java) | 34 | 9 | 79.1% |
| [ghidradwarfforge/output/AttachmentRecoveryInvocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentRecoveryInvocation.java) | 79 | 2 | 97.5% |
| [ghidradwarfforge/output/AttachmentTargetStore.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentTargetStore.java) | 47 | 6 | 88.7% |
| [ghidradwarfforge/output/AttachmentTransaction.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentTransaction.java) | 254 | 15 | 94.4% |
| [ghidradwarfforge/output/AttachmentValidator.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/AttachmentValidator.java) | 0 | 204 | 0.0% |
| [ghidradwarfforge/output/BuildIdFileLock.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/BuildIdFileLock.java) | 56 | 9 | 86.2% |
| [ghidradwarfforge/output/BuildIdHelper.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/BuildIdHelper.java) | 0 | 179 | 0.0% |
| [ghidradwarfforge/output/BuildIdInstallation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/BuildIdInstallation.java) | 0 | 417 | 0.0% |
| [ghidradwarfforge/output/BuildIdRecords.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/BuildIdRecords.java) | 24 | 39 | 38.1% |
| [ghidradwarfforge/output/CompanionArtifactPublisher.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CompanionArtifactPublisher.java) | 138 | 26 | 84.1% |
| [ghidradwarfforge/output/CoverageComparison.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageComparison.java) | 113 | 1 | 99.1% |
| [ghidradwarfforge/output/CoverageComparisonPresentation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageComparisonPresentation.java) | 32 | 0 | 100.0% |
| [ghidradwarfforge/output/CoveragePresentation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoveragePresentation.java) | 84 | 7 | 92.3% |
| [ghidradwarfforge/output/CoverageReportClaims.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageReportClaims.java) | 454 | 10 | 97.8% |
| [ghidradwarfforge/output/CoverageReportGui.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageReportGui.java) | 0 | 148 | 0.0% |
| [ghidradwarfforge/output/CoverageReportJson.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageReportJson.java) | 322 | 7 | 97.9% |
| [ghidradwarfforge/output/CoverageReportTool.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageReportTool.java) | 85 | 4 | 95.5% |
| [ghidradwarfforge/output/CoverageTypeEvidence.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageTypeEvidence.java) | 62 | 13 | 82.7% |
| [ghidradwarfforge/output/CoverageVariableComparison.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CoverageVariableComparison.java) | 118 | 1 | 99.2% |
| [ghidradwarfforge/output/CxxSelection.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/CxxSelection.java) | 96 | 24 | 80.0% |
| [ghidradwarfforge/output/DebuglinkBasename.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/DebuglinkBasename.java) | 29 | 5 | 85.3% |
| [ghidradwarfforge/output/ExportArtifactHashBinding.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ExportArtifactHashBinding.java) | 67 | 1 | 98.5% |
| [ghidradwarfforge/output/ExportReport.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ExportReport.java) | 392 | 13 | 96.8% |
| [ghidradwarfforge/output/ExportReportClaims.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ExportReportClaims.java) | 233 | 7 | 97.1% |
| [ghidradwarfforge/output/FileDigests.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/FileDigests.java) | 32 | 4 | 88.9% |
| [ghidradwarfforge/output/FileSystemPaths.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/FileSystemPaths.java) | 13 | 3 | 81.3% |
| [ghidradwarfforge/output/FirmwareInputs.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/FirmwareInputs.java) | 36 | 1 | 97.3% |
| [ghidradwarfforge/output/FormatterSelection.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/FormatterSelection.java) | 24 | 1 | 96.0% |
| [ghidradwarfforge/output/LinuxAtomicRename.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxAtomicRename.java) | 23 | 7 | 76.7% |
| [ghidradwarfforge/output/LinuxAttachmentHost.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxAttachmentHost.java) | 0 | 87 | 0.0% |
| [ghidradwarfforge/output/LinuxAttachmentMount.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxAttachmentMount.java) | 53 | 2 | 96.4% |
| [ghidradwarfforge/output/LinuxBuildIdHost.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxBuildIdHost.java) | 21 | 41 | 33.9% |
| [ghidradwarfforge/output/LinuxDirectorySync.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxDirectorySync.java) | 60 | 4 | 93.8% |
| [ghidradwarfforge/output/LinuxFileMetadata.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxFileMetadata.java) | 99 | 103 | 49.0% |
| [ghidradwarfforge/output/LinuxMetadataVisibility.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/LinuxMetadataVisibility.java) | 0 | 69 | 0.0% |
| [ghidradwarfforge/output/MmioSelection.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/MmioSelection.java) | 75 | 1 | 98.7% |
| [ghidradwarfforge/output/OutputPathPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/OutputPathPolicy.java) | 33 | 2 | 94.3% |
| [ghidradwarfforge/output/ReportFileSave.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ReportFileSave.java) | 14 | 0 | 100.0% |
| [ghidradwarfforge/output/ReportJsonReader.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ReportJsonReader.java) | 133 | 8 | 94.3% |
| [ghidradwarfforge/output/ReportValueReader.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ReportValueReader.java) | 87 | 1 | 98.9% |
| [ghidradwarfforge/output/SourceBundle.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/SourceBundle.java) | 185 | 4 | 97.9% |
| [ghidradwarfforge/output/SourceBundleFiles.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/SourceBundleFiles.java) | 100 | 14 | 87.7% |
| [ghidradwarfforge/output/SourceBundleStore.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/SourceBundleStore.java) | 96 | 4 | 96.0% |
| [ghidradwarfforge/output/StrictDwarfCheck.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/StrictDwarfCheck.java) | 0 | 66 | 0.0% |
| [ghidradwarfforge/output/StrictDwarfReport.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/StrictDwarfReport.java) | 106 | 2 | 98.1% |
| [ghidradwarfforge/output/UnwindEvidenceJson.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/UnwindEvidenceJson.java) | 204 | 1 | 99.5% |
| [ghidradwarfforge/output/ValidatorInput.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ValidatorInput.java) | 35 | 5 | 87.5% |
| [ghidradwarfforge/output/ValidatorSupervisor.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/ValidatorSupervisor.java) | 145 | 22 | 86.8% |
| [ghidradwarfforge/output/WindowsAttachmentHost.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsAttachmentHost.java) | 0 | 83 | 0.0% |
| [ghidradwarfforge/output/WindowsAttachmentMetadata.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsAttachmentMetadata.java) | 0 | 43 | 0.0% |
| [ghidradwarfforge/output/WindowsAttachmentPrivilege.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsAttachmentPrivilege.java) | 0 | 76 | 0.0% |
| [ghidradwarfforge/output/WindowsBackupStreams.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsBackupStreams.java) | 0 | 85 | 0.0% |
| [ghidradwarfforge/output/WindowsDirectorySync.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsDirectorySync.java) | 0 | 97 | 0.0% |
| [ghidradwarfforge/output/WindowsFileMetadata.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsFileMetadata.java) | 0 | 185 | 0.0% |
| [ghidradwarfforge/output/WindowsFileRename.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsFileRename.java) | 0 | 70 | 0.0% |
| [ghidradwarfforge/output/WindowsFileSecurity.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/output/WindowsFileSecurity.java) | 0 | 71 | 0.0% |
| [ghidradwarfforge/performance/ExportPhase.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/performance/ExportPhase.java) | 14 | 0 | 100.0% |
| [ghidradwarfforge/source/AnnotatedSourceFile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/AnnotatedSourceFile.java) | 120 | 3 | 97.6% |
| [ghidradwarfforge/source/AnnotationLimits.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/AnnotationLimits.java) | 0 | 15 | 0.0% |
| [ghidradwarfforge/source/AnnotationText.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/AnnotationText.java) | 44 | 0 | 100.0% |
| [ghidradwarfforge/source/FunctionStaticPolicy.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/FunctionStaticPolicy.java) | 18 | 1 | 94.7% |
| [ghidradwarfforge/source/SourceContextMode.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/SourceContextMode.java) | 0 | 14 | 0.0% |
| [ghidradwarfforge/source/SourcePartitionPlan.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/SourcePartitionPlan.java) | 99 | 4 | 96.1% |
| [ghidradwarfforge/source/SyntheticSourceFile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/source/SyntheticSourceFile.java) | 128 | 14 | 90.1% |
| [ghidradwarfforge/targets/Aarch64ParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/Aarch64ParameterAllocation.java) | 74 | 8 | 90.2% |
| [ghidradwarfforge/targets/ArmCompositeParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/ArmCompositeParameterAllocation.java) | 85 | 3 | 96.6% |
| [ghidradwarfforge/targets/ArmHfaParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/ArmHfaParameterAllocation.java) | 90 | 3 | 96.8% |
| [ghidradwarfforge/targets/CxxAbiProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/CxxAbiProfile.java) | 25 | 1 | 96.2% |
| [ghidradwarfforge/targets/I386ParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/I386ParameterAllocation.java) | 89 | 12 | 88.1% |
| [ghidradwarfforge/targets/MipsWideParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/MipsWideParameterAllocation.java) | 139 | 7 | 95.2% |
| [ghidradwarfforge/targets/TargetParameterAllocation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/TargetParameterAllocation.java) | 14 | 1 | 93.3% |
| [ghidradwarfforge/targets/UnwindAbiProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/UnwindAbiProfile.java) | 115 | 3 | 97.5% |
| [ghidradwarfforge/targets/UnwindRelocationProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/UnwindRelocationProfile.java) | 33 | 0 | 100.0% |
| [ghidradwarfforge/targets/UnwindSectionProfile.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/targets/UnwindSectionProfile.java) | 7 | 0 | 100.0% |
| [ghidradwarfforge/types/ClassScopeModel.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/ClassScopeModel.java) | 131 | 3 | 97.8% |
| [ghidradwarfforge/types/ClassScopeNames.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/ClassScopeNames.java) | 59 | 0 | 100.0% |
| [ghidradwarfforge/types/DebuggerCallRestrictions.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/DebuggerCallRestrictions.java) | 41 | 0 | 100.0% |
| [ghidradwarfforge/types/FunctionRelations.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/FunctionRelations.java) | 44 | 0 | 100.0% |
| [ghidradwarfforge/types/GlobalScopeNames.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/GlobalScopeNames.java) | 36 | 0 | 100.0% |
| [ghidradwarfforge/types/InheritanceModel.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/InheritanceModel.java) | 94 | 1 | 98.9% |
| [ghidradwarfforge/types/LexicalScopeModel.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/LexicalScopeModel.java) | 87 | 1 | 98.9% |
| [ghidradwarfforge/types/ProgramTypeModel.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/ProgramTypeModel.java) | 204 | 22 | 90.3% |
| [ghidradwarfforge/types/TypeGraph.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/TypeGraph.java) | 134 | 12 | 91.8% |
| [ghidradwarfforge/types/VtableEvidence.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/types/VtableEvidence.java) | 10 | 1 | 90.9% |
| [ghidradwarfforge/unwind/CallFramePlan.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/CallFramePlan.java) | 63 | 4 | 94.0% |
| [ghidradwarfforge/unwind/GhidraUnwindCalls.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/GhidraUnwindCalls.java) | 84 | 2 | 97.7% |
| [ghidradwarfforge/unwind/GhidraUnwindFrames.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/GhidraUnwindFrames.java) | 62 | 3 | 95.4% |
| [ghidradwarfforge/unwind/GhidraUnwindInstructions.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/GhidraUnwindInstructions.java) | 168 | 18 | 90.3% |
| [ghidradwarfforge/unwind/GhidraUnwindRecovery.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/GhidraUnwindRecovery.java) | 76 | 4 | 95.0% |
| [ghidradwarfforge/unwind/OriginalFrameRanges.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/OriginalFrameRanges.java) | 162 | 3 | 98.2% |
| [ghidradwarfforge/unwind/UnwindCalls.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/UnwindCalls.java) | 120 | 2 | 98.4% |
| [ghidradwarfforge/unwind/UnwindFlow.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/UnwindFlow.java) | 211 | 4 | 98.1% |
| [ghidradwarfforge/unwind/UnwindFrameRows.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/UnwindFrameRows.java) | 83 | 1 | 98.8% |
| [ghidradwarfforge/unwind/UnwindOptions.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/UnwindOptions.java) | 56 | 5 | 91.8% |
| [ghidradwarfforge/unwind/UnwindStackSeparation.java](https://github.com/zwilcox/GhidraDwarfForge/blob/f8ee3b7a83bbf857faa8aae43c61669537f3e4bb/src/main/java/ghidradwarfforge/unwind/UnwindStackSeparation.java) | 73 | 1 | 98.6% |

## Instrumented test tasks

- `aarch64AbiSelectionSmoke`
- `aarch64ParameterAllocationSmoke`
- `addressNormalizerSmoke`
- `allocationDecompilerSmoke`
- `annotatedSourceSmoke`
- `annotationTextSmoke`
- `arm32CallPolicySmoke`
- `arm32FunctionAliasSymbolsSmoke`
- `arm32ModeSymbolsSmoke`
- `arm32SectionModesSmoke`
- `armCompositeParameterAllocationSmoke`
- `armHfaParameterAllocationSmoke`
- `artifactPairPublisherSmoke`
- `attachmentExportBindingSmoke`
- `attachmentFileStoreSmoke`
- `attachmentGuiProcessSmoke`
- `attachmentHelperSmoke`
- `attachmentInvocationSmoke`
- `attachmentOperationSmoke`
- `attachmentPreparationSmoke`
- `attachmentProtocolSmoke`
- `attachmentReceiptStoreSmoke`
- `attachmentRecoveryInvocationSmoke`
- `attachmentTargetStoreSmoke`
- `attachmentTransactionSmoke`
- `boundedSwitchProofSmoke`
- `buildIdFileLockSmoke`
- `buildIdRecordsSmoke`
- `callArgumentFlowSmoke`
- `callEntryContractSmoke`
- `callFrameEncoderSmoke`
- `callMemoryEffectsSmoke`
- `callOriginSymbolsSmoke`
- `callSiteEvidenceSmoke`
- `callValueSmoke`
- `callingConventionPolicySmoke`
- `classBindingEvidenceSmoke`
- `classScopeExtractionSmoke`
- `classScopeModelSmoke`
- `classScopeNamesSmoke`
- `classScopeSmoke`
- `companionArtifactPublisherSmoke`
- `compilerCallPolicySmoke`
- `compositeRegisterPrefixSmoke`
- `compositeValueFlowSmoke`
- `cortexM3ProfileSmoke`
- `coverageComparisonPresentationSmoke`
- `coverageComparisonSmoke`
- `coveragePresentationSmoke`
- `coverageReportClaimsSmoke`
- `coverageReportJsonSmoke`
- `coverageTypeEvidenceSmoke`
- `coverageVariableComparisonSmoke`
- `curatedThunkSmoke`
- `customCallStorageSmoke`
- `cxxProfileSmoke`
- `debugCompressionSmoke`
- `debuglinkBasenameSmoke`
- `debuglinkCandidateContentSmoke`
- `declarationBindingEvidenceSmoke`
- `defaultTypeIdentitySmoke`
- `definedRegisterLocalSmoke`
- `delayedReturnPrefixSmoke`
- `directLeafCallSmoke`
- `dwarfAddressRangesSmoke`
- `dwarfInfoRepairSmoke`
- `dwarfLineTableSmoke`
- `dwarfLocationListsSmoke`
- `dwarfRangeListsSmoke`
- `dwarfTargetSmoke`
- `dynamicCompositeOrderSmoke`
- `dynamicParameterStorageSmoke`
- `dynamicSymbolMirrorSmoke`
- `elfBuildIdSmoke`
- `elfCodeBytesSmoke`
- `elfCopyCancellationSmoke`
- `elfImageBaseSmoke`
- `elfImageReaderSmoke`
- `elfRelocatedPointersSmoke`
- `elfRelocationEffectsSmoke`
- `elfRuntimeRelocationsSmoke`
- `executableProgramBytesSmoke`
- `existingDebugSidecarSmoke`
- `exportArtifactHashBindingSmoke`
- `exportConsistencySmoke`
- `exportCoverageSmoke`
- `exportPhaseSmoke`
- `exportReportClaimsSmoke`
- `exportReportCoverageSmoke`
- `exportReportDetailsSmoke`
- `exportReportSmoke`
- `extendedSectionNumberingSmoke`
- `externalFunctionInventorySmoke`
- `fileDigestsSmoke`
- `firmwareInputsSmoke`
- `firmwareMemoryMapSmoke`
- `floatingTypeLayoutSmoke`
- `formalFunctionReturnSmoke`
- `formatterPlanSmoke`
- `functionAliasSymbolsSmoke`
- `functionEntrySmoke`
- `functionPointerCallPolicySmoke`
- `functionRelationExtractionSmoke`
- `functionRelationsSmoke`
- `ghidraArm32FunctionModesSmoke`
- `ghidraArm32SectionModesSmoke`
- `ghidraArmBe8ProfileSmoke`
- `ghidraCortexM3ProfileSmoke`
- `ghidraFirmwareMemoryMapSmoke`
- `ghidraFunctionAliasesSmoke`
- `ghidraImageBaseSmoke`
- `ghidraInstructionEvidenceSmoke`
- `ghidraMmioEvidenceSmoke`
- `ghidraTargetAgreementSmoke`
- `ghidraUnwindCallsSmoke`
- `ghidraUnwindInstructionsSmoke`
- `ghidraVariableIdentitySmoke`
- `globalScopeNamesSmoke`
- `i386AbiSelectionSmoke`
- `i386ParameterAllocationSmoke`
- `indirectParameterStorageSmoke`
- `inheritanceBindingEvidenceSmoke`
- `inheritanceModelSmoke`
- `inspectedCallsSmoke`
- `intraInstructionFlowSmoke`
- `laterRegisterLocalSmoke`
- `lexicalScopeEvidenceSmoke`
- `lexicalScopeModelSmoke`
- `localCallLifetimeSmoke`
- `localDefinitionFlowSmoke`
- `localMappingsSmoke`
- `localSymbolMergeSmoke`
- `locationCoverageSmoke`
- `locationEmissionPlanSmoke`
- `matchedElfAllocationsSmoke`
- `matchedElfPrefixSmoke`
- `mergedLocalLifetimeSmoke`
- `mipsAbiFlagsSmoke`
- `mipsAggregateCallPolicySmoke`
- `mipsFloatingCallPolicySmoke`
- `mipsFp32PairSmoke`
- `mipsFunctionAliasSymbolsSmoke`
- `mipsN32ParameterAllocationSmoke`
- `mipsWideCallPolicySmoke`
- `mixedParameterPrefixSmoke`
- `mutableStackMappingsSmoke`
- `objectParameterSmoke`
- `opaqueRegisterEffectsSmoke`
- `originalFrameRangesSmoke`
- `originalFrameSourcesSmoke`
- `outputPathPolicySmoke`
- `outsideBodyFlowSmoke`
- `ownedDebuglinkCandidateSmoke`
- `packagedNativeLibrariesSmoke`
- `pathTraversalSmoke`
- `qualifiedFunctionNameSmoke`
- `recoveredParameterSmoke`
- `recoveredReturnSmoke`
- `registerAliasSmoke`
- `registerBodyCoverageSmoke`
- `registerByteSliceFlowSmoke`
- `registerCopyChainSmoke`
- `registerCopySmoke`
- `registerPrefixSmoke`
- `reportValueReaderSmoke`
- `secondRegisterCopySmoke`
- `sectionlessDynamicSymbolsSmoke`
- `sectionlessUnwindSmoke`
- `sourceBundleFilesSmoke`
- `sourceBundleSmoke`
- `sourceBundleStoreSmoke`
- `sourceCoverageInventorySmoke`
- `sourceCoverageSmoke`
- `sourcePartitionSmoke`
- `stackControlFlowSmoke`
- `stackFirstUseSmoke`
- `stackLocalIdentitySmoke`
- `stackLocalLifetimeSmoke`
- `stackSpillSmoke`
- `stackValueFlowSmoke`
- `staticBindingEvidenceSmoke`
- `staticRecoverySmoke`
- `staticScopeExtractionSmoke`
- `strictDwarfReportSmoke`
- `syntheticSourceSmoke`
- `tailStateProofSmoke`
- `terminalStackValueSmoke`
- `truncatedSpaceStoreSmoke`
- `truncatedStackDepthSmoke`
- `typeCoverageSmoke`
- `typeGraphEvidenceSmoke`
- `typeGraphSmoke`
- `unwindAbiProfileSmoke`
- `unwindCallsSmoke`
- `unwindEvidenceJsonSmoke`
- `unwindFlowSmoke`
- `unwindFrameRowsSmoke`
- `unwindOptionsSmoke`
- `unwindStackSeparationSmoke`
- `upperAliasValueFlowSmoke`
- `validatorSupervisorSmoke`
- `variableCoverageInventorySmoke`
- `variableStorageSmoke`
- `vtableBindingEvidenceSmoke`
- `vtableSymbolsSmoke`
