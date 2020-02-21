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

        private Lazy<INamedTypeSymbol>                     ObjectTypeCached;
        public INamedTypeSymbol                            ObjectType => ObjectTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     StringTypeCached;
        public INamedTypeSymbol                            StringType            => StringTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     CharTypeCached;
        public INamedTypeSymbol                            CharType              => CharTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     BooleanTypeCached;
        public INamedTypeSymbol                            BooleanType           => BooleanTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     ByteTypeCached;
        public INamedTypeSymbol                            ByteType              => ByteTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     SByteTypeCached;
        public INamedTypeSymbol                            SByteType             => SByteTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     Int16TypeCached;
        public INamedTypeSymbol                            Int16Type             => Int16TypeCached.Value;

        private Lazy<INamedTypeSymbol>                     UInt16TypeCached;
        public INamedTypeSymbol                            UInt16Type            => UInt16TypeCached.Value;

        private Lazy<INamedTypeSymbol>                     Int32TypeCached;
        public INamedTypeSymbol                            Int32Type             => Int32TypeCached.Value;

        private Lazy<INamedTypeSymbol>                     UInt32TypeCached;
        public INamedTypeSymbol                            UInt32Type            => UInt32TypeCached.Value;

        private Lazy<INamedTypeSymbol>                     Int64TypeCached;
        public INamedTypeSymbol                            Int64Type             => Int64TypeCached.Value;

        private Lazy<INamedTypeSymbol>                     UInt64TypeCached;
        public INamedTypeSymbol                            UInt64Type            => UInt64TypeCached.Value;

        private Lazy<INamedTypeSymbol>                     IntPtrTypeCached;
        public INamedTypeSymbol                            IntPtrType            => IntPtrTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     UIntPtrTypeCached;
        public INamedTypeSymbol                            UIntPtrType           => UIntPtrTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     SingleTypeCached;
        public INamedTypeSymbol                            SingleType            => SingleTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     DoubleTypeCached;
        public INamedTypeSymbol                            DoubleType            => DoubleTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     DecimalTypeCached;
        public INamedTypeSymbol                            DecimalType           => DecimalTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     EnumTypeCached;
        public INamedTypeSymbol                            EnumType              => EnumTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     DateTimeTypeCached;
        public INamedTypeSymbol                            DateTimeType          => DateTimeTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     DateTimeOffsetTypeCached;
        public INamedTypeSymbol                            DateTimeOffsetType    => DateTimeOffsetTypeCached.Value;

        private Lazy<INamedTypeSymbol>                     GuidTypeCached;
        public INamedTypeSymbol                            GuidType              => GuidTypeCached.Value;

        /// <summary>
        /// Initialize the state with no variable recorded yet.
        /// </summary>
        /// <param name="ctx">Context used to resolve symbol.</param>
        public ExecutionState(SyntaxNodeAnalysisContext ctx)
        {
            AnalysisContext = ctx;
            Variables = new Dictionary<string, VariableState>();
            ObjectTypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Object));
            StringTypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_String));
            CharTypeCached              = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Char));
            BooleanTypeCached           = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Boolean));
            ByteTypeCached              = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Byte));
            SByteTypeCached             = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_SByte));
            Int16TypeCached             = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Int16));
            UInt16TypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UInt16));
            Int32TypeCached             = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Int32));
            UInt32TypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UInt32));
            Int64TypeCached             = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Int64));
            UInt64TypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UInt64));
            IntPtrTypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_IntPtr));
            UIntPtrTypeCached           = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_UIntPtr));
            SingleTypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Single));
            DoubleTypeCached            = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Double));
            DecimalTypeCached           = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Decimal));
            EnumTypeCached              = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_Enum));
            DateTimeTypeCached          = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetSpecialType(SpecialType.System_DateTime));
            DateTimeOffsetTypeCached    = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetTypeByMetadataName("System.DateTimeOffset"));
            GuidTypeCached              = new Lazy<INamedTypeSymbol>(() => ctx.Compilation.GetTypeByMetadataName("System.Guid"));
        }

        public ExecutionState(ExecutionState other)
        {
            AnalysisContext = other.AnalysisContext;
            Variables       = new Dictionary<string, VariableState>(other.VariableStates.Count);
            ObjectTypeCached            = other.ObjectTypeCached;
            StringTypeCached            = other.StringTypeCached;
            CharTypeCached              = other.CharTypeCached;
            BooleanTypeCached           = other.BooleanTypeCached;
            ByteTypeCached              = other.ByteTypeCached;
            SByteTypeCached             = other.SByteTypeCached;
            Int16TypeCached             = other.Int16TypeCached;
            UInt16TypeCached            = other.UInt16TypeCached;
            Int32TypeCached             = other.Int32TypeCached;
            UInt32TypeCached            = other.UInt32TypeCached;
            Int64TypeCached             = other.Int64TypeCached;
            UInt64TypeCached            = other.UInt64TypeCached;
            IntPtrTypeCached            = other.IntPtrTypeCached;
            UIntPtrTypeCached           = other.UIntPtrTypeCached;
            SingleTypeCached            = other.SingleTypeCached;
            DoubleTypeCached            = other.DoubleTypeCached;
            DecimalTypeCached           = other.DecimalTypeCached;
            EnumTypeCached              = other.EnumTypeCached;
            DateTimeTypeCached          = other.DateTimeTypeCached;
            DateTimeOffsetTypeCached    = other.DateTimeOffsetTypeCached;
            GuidTypeCached              = other.GuidTypeCached;

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

        private void MergeCachedTypes(ExecutionState state)
        {
            // prone for race conditions, but small optimization
            if (!ObjectTypeCached.IsValueCreated && state.ObjectTypeCached.IsValueCreated)
                ObjectTypeCached = state.ObjectTypeCached;
            if (!StringTypeCached.IsValueCreated && state.StringTypeCached.IsValueCreated)
                StringTypeCached = state.StringTypeCached;
            if (!CharTypeCached.IsValueCreated && state.CharTypeCached.IsValueCreated)
                CharTypeCached = state.CharTypeCached;
            if (!BooleanTypeCached.IsValueCreated && state.BooleanTypeCached.IsValueCreated)
                BooleanTypeCached = state.BooleanTypeCached;
            if (!ByteTypeCached.IsValueCreated && state.ByteTypeCached.IsValueCreated)
                ByteTypeCached = state.ByteTypeCached;
            if (!SByteTypeCached.IsValueCreated && state.SByteTypeCached.IsValueCreated)
                SByteTypeCached = state.SByteTypeCached;
            if (!Int16TypeCached.IsValueCreated && state.Int16TypeCached.IsValueCreated)
                Int16TypeCached = state.Int16TypeCached;
            if (!UInt16TypeCached.IsValueCreated && state.UInt16TypeCached.IsValueCreated)
                UInt16TypeCached = state.UInt16TypeCached;
            if (!Int32TypeCached.IsValueCreated && state.Int32TypeCached.IsValueCreated)
                Int32TypeCached = state.Int32TypeCached;
            if (!UInt32TypeCached.IsValueCreated && state.UInt32TypeCached.IsValueCreated)
                UInt32TypeCached = state.UInt32TypeCached;
            if (!Int64TypeCached.IsValueCreated && state.Int64TypeCached.IsValueCreated)
                Int64TypeCached = state.Int64TypeCached;
            if (!UInt64TypeCached.IsValueCreated && state.UInt64TypeCached.IsValueCreated)
                UInt64TypeCached = state.UInt64TypeCached;
            if (!IntPtrTypeCached.IsValueCreated && state.IntPtrTypeCached.IsValueCreated)
                IntPtrTypeCached = state.IntPtrTypeCached;
            if (!UIntPtrTypeCached.IsValueCreated && state.UIntPtrTypeCached.IsValueCreated)
                UIntPtrTypeCached = state.UIntPtrTypeCached;
            if (!SingleTypeCached.IsValueCreated && state.SingleTypeCached.IsValueCreated)
                SingleTypeCached = state.SingleTypeCached;
            if (!DoubleTypeCached.IsValueCreated && state.DoubleTypeCached.IsValueCreated)
                DoubleTypeCached = state.DoubleTypeCached;
            if (!DecimalTypeCached.IsValueCreated && state.DecimalTypeCached.IsValueCreated)
                DecimalTypeCached = state.DecimalTypeCached;
            if (!EnumTypeCached.IsValueCreated && state.EnumTypeCached.IsValueCreated)
                EnumTypeCached = state.EnumTypeCached;
            if (!DateTimeTypeCached.IsValueCreated && state.DateTimeTypeCached.IsValueCreated)
                DateTimeTypeCached = state.DateTimeTypeCached;
            if (!DateTimeOffsetTypeCached.IsValueCreated && state.DateTimeOffsetTypeCached.IsValueCreated)
                DateTimeOffsetTypeCached = state.DateTimeOffsetTypeCached;
            if (!GuidTypeCached.IsValueCreated && state.GuidTypeCached.IsValueCreated)
                GuidTypeCached = state.GuidTypeCached;
        }

        public void Replace(ExecutionState other)
        {
            AnalysisContext = other.AnalysisContext;
            Variables       = other.Variables;

            MergeCachedTypes(other);
        }

        public void Merge(ExecutionState other)
        {
            MergeCachedTypes(other);

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
