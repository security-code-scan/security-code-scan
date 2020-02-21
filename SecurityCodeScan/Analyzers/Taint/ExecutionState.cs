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
        }

        public ExecutionState(ExecutionState other)
        {
            AnalysisContext = other.AnalysisContext;
            Variables       = new Dictionary<string, VariableState>(other.VariableStates.Count);
            ObjectTypeCached            = other.ObjectTypeCached;
            StringTypeCached            = other.StringTypeCached;

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
