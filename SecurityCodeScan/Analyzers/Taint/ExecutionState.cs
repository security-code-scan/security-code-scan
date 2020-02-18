using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Execution state at a given statement. It is altered after each statement are evaluated.
    /// 
    /// Objectives of this class:
    ///  * Keep the state of each variable
    ///  * Keep reference to utilities that are require along the taint analysis. (Such as resolving symbol)
    /// </summary>
    internal class ExecutionState
    {
        public  SyntaxNodeAnalysisContext                  AnalysisContext       { get; private set; }
        public  IReadOnlyDictionary<string, VariableState> VariableStates        => Variables;
        private Dictionary<string, VariableState>          Variables             { get; set; }

        private Lazy<INamedTypeSymbol>                     _StringType;
        public INamedTypeSymbol                            StringType            => _StringType.Value;
        private Lazy<INamedTypeSymbol>                     _CharType;
        public INamedTypeSymbol                            CharType              => _CharType.Value;
        private Lazy<INamedTypeSymbol>                     _BooleanType;
        public INamedTypeSymbol                            BooleanType           => _BooleanType.Value;
        private Lazy<INamedTypeSymbol>                     _ByteType;
        public INamedTypeSymbol                            ByteType              => _ByteType.Value;
        private Lazy<INamedTypeSymbol>                     _SByteType;
        public INamedTypeSymbol                            SByteType             => _SByteType.Value;
        private Lazy<INamedTypeSymbol>                     _Int16Type;
        public INamedTypeSymbol                            Int16Type             => _Int16Type.Value;
        private Lazy<INamedTypeSymbol>                     _UInt16Type;
        public INamedTypeSymbol                            UInt16Type            => _UInt16Type.Value;
        private Lazy<INamedTypeSymbol>                     _Int32Type;
        public INamedTypeSymbol                            Int32Type             => _Int32Type.Value;
        private Lazy<INamedTypeSymbol>                     _UInt32Type;
        public INamedTypeSymbol                            UInt32Type            => _UInt32Type.Value;
        private Lazy<INamedTypeSymbol>                     _Int64Type;
        public INamedTypeSymbol                            Int64Type             => _Int64Type.Value;
        private Lazy<INamedTypeSymbol>                     _UInt64Type;
        public INamedTypeSymbol                            UInt64Type            => _UInt64Type.Value;
        private Lazy<INamedTypeSymbol>                     _IntPtrType;
        public INamedTypeSymbol                            IntPtrType            => _IntPtrType.Value;
        private Lazy<INamedTypeSymbol>                     _UIntPtrType;
        public INamedTypeSymbol                            UIntPtrType           => _UIntPtrType.Value;
        private Lazy<INamedTypeSymbol>                     _SingleType;
        public INamedTypeSymbol                            SingleType            => _SingleType.Value;
        private Lazy<INamedTypeSymbol>                     _DoubleType;
        public INamedTypeSymbol                            DoubleType            => _DoubleType.Value;
        private Lazy<INamedTypeSymbol>                     _DecimalType;
        public INamedTypeSymbol                            DecimalType           => _DecimalType.Value;
        private Lazy<INamedTypeSymbol>                     _EnumType;
        public INamedTypeSymbol                            EnumType              => _EnumType.Value;
        private Lazy<INamedTypeSymbol>                     _DateTimeType;
        public INamedTypeSymbol                            DateTimeType          => _DateTimeType.Value;
        private Lazy<INamedTypeSymbol>                     _DateTimeOffsetType;
        public INamedTypeSymbol                            DateTimeOffsetType    => _DateTimeOffsetType.Value;
        private Lazy<INamedTypeSymbol>                     _GuidType;
        public INamedTypeSymbol                            GuidType              => _GuidType.Value;

        /// <summary>
        /// Initialize the state with no variable recorded yet.
        /// </summary>
        /// <param name="ctx">Context used to resolve symbol.</param>
        public ExecutionState(SyntaxNodeAnalysisContext ctx)
        {
            AnalysisContext = ctx;
            Variables = new Dictionary<string, VariableState>();
            _StringType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_String));
            _CharType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Char));
            _BooleanType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Boolean));
            _ByteType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Byte));
            _SByteType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_SByte));
            _Int16Type = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Int16));
            _UInt16Type = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UInt16));
            _Int32Type = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Int32));
            _UInt32Type = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UInt32));
            _Int64Type = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Int64));
            _UInt64Type = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UInt64));
            _IntPtrType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_IntPtr));
            _UIntPtrType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UIntPtr));
            _SingleType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Single));
            _DoubleType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Double));
            _DecimalType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Decimal));
            _EnumType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Enum));
            _DateTimeType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_DateTime));
            _DateTimeOffsetType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetTypeByMetadataName("System.DateTimeOffset"));
            _GuidType = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetTypeByMetadataName("System.Guid"));
        }

        public ExecutionState(ExecutionState other)
        {
            AnalysisContext = other.AnalysisContext;
            Variables       = new Dictionary<string, VariableState>(other.VariableStates.Count);
            _StringType     = other._StringType;

            var otherVariableStateToNew = new Dictionary<VariableState, VariableState>();
            foreach (var otherVariablePair in other.VariableStates)
            {
                CollectVariableStates(otherVariableStateToNew, otherVariablePair.Value);
                Variables.Add(otherVariablePair.Key, otherVariableStateToNew[otherVariablePair.Value]);
            }

            foreach (var otherToNewPair in otherVariableStateToNew)
            {
                foreach (var property in otherToNewPair.Key.PropertyStates)
                {
                    otherToNewPair.Value.AddProperty(property.Key, otherVariableStateToNew[property.Value]);
                }
            }
        }

        private void CollectVariableStates(Dictionary<VariableState, VariableState> otherVariableStateToNew, VariableState other)
        {
            if (otherVariableStateToNew.ContainsKey(other))
                return;

            otherVariableStateToNew.Add(other, new VariableState(other.Node, other.Taint, other.Value));

            foreach (var otherVariablePair in other.PropertyStates)
            {
                CollectVariableStates(otherVariableStateToNew, otherVariablePair.Value);
            }
        }

        public void Replace(ExecutionState state)
        {
            AnalysisContext = state.AnalysisContext;
            Variables       = state.Variables;
            if (!_StringType.IsValueCreated && state._StringType.IsValueCreated) // prone for race conditions, but small optimization
                _StringType = state._StringType;
        }

        public void Merge(ExecutionState other)
        {
            var queue = new Queue<KeyValuePair<VariableState, VariableState>>();
            var otherToSelf = new Dictionary<VariableState, VariableState>();

            foreach (var otherVariableState in other.VariableStates)
            {
                if (!Variables.TryGetValue(otherVariableState.Key, out var selfVariableState))
                {
                    selfVariableState = new VariableState(otherVariableState.Value.Node,
                                                          otherVariableState.Value.Taint,
                                                          otherVariableState.Value.Value);

                    Variables.Add(otherVariableState.Key, selfVariableState);
                }

                if (!otherToSelf.ContainsKey(otherVariableState.Value))
                {
                    queue.Enqueue(new KeyValuePair<VariableState, VariableState>(otherVariableState.Value, selfVariableState));
                    otherToSelf.Add(otherVariableState.Value, selfVariableState);
                }
            }

            VariableState.Merge(queue, otherToSelf);
        }

        public void AddNewValue(string identifier, VariableState value)
        {
            if (VariableStates.ContainsKey(identifier)) //New variable in a different scope
            {
#if DEBUG
                Logger.Log("Removing existing state for " + identifier);
#endif
                Variables.Remove(identifier);
            }

#if DEBUG
            Logger.Log($"Adding state for {identifier} ({value})");
#endif
            Variables.Add(identifier, value);
        }

        public void AddOrUpdateValue(string identifier, VariableState value)
        {
            if (VariableStates.ContainsKey(identifier)) //Override existing value
            {
                VariableStates[identifier].Replace(value);
#if DEBUG
                Logger.Log($"Updating state for {identifier} ({value})");
#endif
            }
            else
            {
                //Unexpected state
#if DEBUG
                Logger.Log($"Adding state for {identifier} ({value})");
#endif

                Variables.Add(identifier, value);
            }
        }

        /// <summary>
        /// Resolve semantic class name of a given variable reference.
        /// </summary>
        /// <param name="node">Expression to evaluate</param>
        /// <returns>The resolved symbol with the complete class name and method name.</returns>
        public ISymbol GetSymbol(SyntaxNode node)
        {
            try
            {
                return node != null ? AnalysisContext.SemanticModel.GetSymbolInfo(node).Symbol : null;
            }
            catch (ArgumentException) // todo: should be not needed, remove and test
            {
                return null; // Syntax node is not within syntax tree
            }
        }
    }
}
