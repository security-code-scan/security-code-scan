using System.Collections.Generic;

using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis;
using System;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    /// <summary>
    /// Execution state at a given statement. It will be alter after each statement are evaluated.
    /// 
    /// Objectives of this class:
    ///  * Keep the state of each variable
    ///  * Keep reference to utilities that are require along the taint analysis. (Such as resolving symbol)
    /// </summary>
    public class ExecutionState
    {
        private bool DebugMode = true;

        public SyntaxNodeAnalysisContext AnalysisContext { get; }
        public IDictionary<string, VariableState> Variables { get; private set; }

        /// <summary>
        /// Initialize the state with no variable recorded yet.
        /// </summary>
        /// <param name="ctx">Context used to resolve symbol.</param>
        public ExecutionState(SyntaxNodeAnalysisContext ctx)
        {
            AnalysisContext = ctx;
            Variables = new Dictionary<string, VariableState>();
        }

        public void AddNewValue(string identifier, VariableState value) {

            if (Variables.ContainsKey(identifier)) //New variable in a different scope
            {
                if (DebugMode) SGLogging.Log("Removing existing state for " + identifier);
                Variables.Remove(identifier);
            }
            if (DebugMode) SGLogging.Log(string.Format("Adding state for {0} ({1})", identifier, value));
            Variables.Add(identifier, value);
        }

        public void MergeValue(string identifier, VariableState value)
        {
            if (Variables.ContainsKey(identifier)) //Override existing value
            {

                var state = Variables[identifier];
                var newState = state.merge(value);
                Variables.Remove(identifier);
                Variables.Add(identifier, newState);
                if (DebugMode) SGLogging.Log(string.Format("Merging state for {0} ({1})", identifier, newState));
            }
            else
            { //Unexpected state
                if (DebugMode) SGLogging.Log(string.Format("Merging state for {0} ({1}) .. /!\\ unexpected state", identifier, value));
                Variables.Add(identifier, value);
            }
        }

        public VariableState GetValueByIdentifier(string identifier)
        {
            VariableState value;
            if (Variables.TryGetValue(identifier, out value))
                return value;

            return new VariableState(value.node, VariableTaint.UNKNOWN);
        }

        /// <summary>
        /// Resolve semantic class name of a given variable reference.
        /// </summary>
        /// <param name="node">Expression to evaluate</param>
        /// <returns>The resolved symbol with the complete class name and method name.</returns>
        public ISymbol GetSymbol(SyntaxNode node) {
            if (node == null) return null;
            return AnalysisContext.SemanticModel.GetSymbolInfo(node).Symbol;
        }

        public void AddTag(string variableAccess, VariableTag httpCookieSecure)
        {
            if (DebugMode)
                SGLogging.Log($"Adding tag '{httpCookieSecure}' to  {variableAccess}");

            VariableState variable;
            if (Variables.TryGetValue(variableAccess, out variable))
                variable.AddTag(httpCookieSecure);
        }
    }
}
