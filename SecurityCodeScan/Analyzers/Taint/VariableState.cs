using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using static SecurityCodeScan.Analyzers.Taint.VariableTaint;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Define the state of variable regarding can it be trust, where does it come from.
    /// </summary>
    public class VariableState
    {
        public VariableTaint Taint { get; private set; }

        /// <summary>
        /// Contains Value only if Taint is constant. Otherwise returns null
        /// </summary>
        public object Value { get; private set; }

        public SyntaxNode Node { get; private set; }

        public  IReadOnlyDictionary<string, VariableState> PropertyStates => Properties;
        private Dictionary<string, VariableState>          Properties { get; set; }

        public VariableState(SyntaxNode node, VariableTaint taint = Unknown, object value = null)
        {
            Taint = taint;
            Value = null;
            if (Taint == Constant)
                Value = value;
            Node = node;
            Properties = new Dictionary<string, VariableState>();
        }

        /// <summary>
        /// Merge two different states. Use it to merge two states then values are concatenated.
        /// </summary>
        public void Merge(VariableState secondState)
        {
            ResolveTaint(secondState.Taint);

            if (secondState.Taint == Constant)
                Value = secondState.Value;

            if (secondState.Taint != Unset)
                Node = secondState.Node;

            foreach (var newPropertyState in secondState.PropertyStates)
            {
                if (Properties.ContainsKey(newPropertyState.Key))
                    Properties[newPropertyState.Key].Merge(newPropertyState.Value);
                else
                    Properties.Add(newPropertyState.Key, newPropertyState.Value);
            }
        }

        public void ResolveTaint(VariableTaint newTaint)
        {
            if (Taint == Unset)
            {
                Taint = newTaint;
            }
            else
            {
                switch (newTaint)
                {
                    case Tainted:
                        Taint = Tainted;
                        break;
                    case Unknown:
                        if (Taint != Tainted)
                            Taint = Unknown;

                        break;
                    case Safe:
                        if (Taint != Tainted && Taint != Unknown)
                            Taint = Safe;

                        break;
                    case Constant:
                    case Unset:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
        }

        /// <summary>
        /// Merge two different states. Use it to merge two states then value is overridden.
        /// </summary>
        public void Replace(VariableState secondState)
        {
            if (secondState.Taint == Unset)
                return;

            Taint = secondState.Taint;
            Value = Taint == Constant ? secondState.Value : null;
            Node  = secondState.Node;

            Properties = secondState.Properties;
        }

        public VariableState AddOrMergeProperty(string identifier, VariableState secondState)
        {
            if (PropertyStates.ContainsKey(identifier))
            {
                PropertyStates[identifier].Replace(secondState);
                ResolveTaint(secondState.Taint);
            }
            else
            {
                Properties.Add(identifier, secondState);
            }

            return this;
        }

        public override string ToString()
        {
            return Taint.ToString();
        }
    }
}
