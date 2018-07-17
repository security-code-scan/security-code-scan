using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using static SecurityCodeScan.Analyzers.Taint.VariableTaint;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Define the state of variable regarding can it be trust, where does it come from.
    /// 
    /// <code>struct</code> was chosen because the execution of the taint analysis will be visited a lot.
    /// This may allow less heap allocation and less garbage collection.
    /// 
    /// <a href="https://msdn.microsoft.com/en-us/library/ms229017.aspx">Choosing Between Class and Struct</a>
    /// </summary>
    public struct VariableState
    {
        private readonly List<VariableTag> VariableTags;

        public VariableTaint Taint { get; }

        public List<VariableTag> Tags
        {
            get
            {
                var tags = new List<VariableTag>(VariableTags);
                foreach (var propertyState in PropertyStates)
                {
                    tags.AddRange(propertyState.Value.Tags);
                }

                return tags;
            }
        }

        public SyntaxNode Node { get; private set; }

        public Dictionary<string, VariableState> PropertyStates { get;  }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="taint">Initial state</param>
        /// <param name="propertyStates">Initial properties</param>
        public VariableState(SyntaxNode node, VariableTaint taint = Unknown, Dictionary<string, VariableState> propertyStates = null, List<VariableTag> tags = null)
        {
            Taint = taint;
            VariableTags = tags ?? new List<VariableTag>();
            Node = node;
            PropertyStates = propertyStates ?? new Dictionary<string, VariableState>();
        }

        /// <summary>
        /// Merge two different states. State are merge if a data structure accept new input or 
        /// if values are concatenate.
        /// </summary>
        /// <param name="secondState"></param>
        /// <returns></returns>
        public VariableState Merge(VariableState secondState)
        {
            var newNode = Node;
            var newTaint = Taint;
            if (Taint == Unset)
            {
                newTaint = secondState.Taint;
            }
            else
            {
                switch (secondState.Taint)
                {
                    case Tainted:
                    newTaint = Tainted;
                    break;
                    case Unknown:
                    if (Taint != Tainted)
                        newTaint = Unknown;

                    break;
                    case Safe:
                    if (Taint != Tainted && Taint != Unknown)
                        newTaint = Safe;

                    break;
                    case Constant:
                    if (Taint == Safe)
                        newTaint = Safe;
                    else if (Taint == Constant)
                        newTaint = Constant;

                    break;
                    case Unset:
                    break;
                    default:
                    throw new ArgumentOutOfRangeException();
                }
            }

            if (secondState.Taint != Unset)
                newNode = secondState.Node;

            // A new instance is made to prevent referencing the current VariableState's parameters
            var vs = new VariableState(newNode, newTaint, PropertyStates, VariableTags);

            // Searches through the new VariableState for new tags
            foreach (var newPropertyState in secondState.PropertyStates)
            {
                vs.PropertyStates.Add(newPropertyState.Key, newPropertyState.Value);
            }

            // Searches through the new VariableState for new tags
            foreach (var newTag in secondState.VariableTags)
            {
                vs.AddTag(newTag);
            }

            return vs;
        }

        public VariableState MergeProperty(string identifier, VariableState secondState)
        {
            if (PropertyStates.ContainsKey(identifier))
                PropertyStates[identifier] = PropertyStates[identifier].Merge(secondState);
            else
                PropertyStates.Add(identifier, secondState);

            return this;
        }

        public override string ToString()
        {
            return Taint.ToString();
        }

        /// <summary>
        /// Will only add a new tag to the list if it is not already present in the list
        /// </summary>
        /// <param name="tag"></param>
        /// <returns>A VariabeState with the updated list</returns>
        public VariableState AddTag(VariableTag tag)
        {
            if (!VariableTags.Contains(tag))
            {
                VariableTags.Add(tag);
            }

            return this;
        }

        public VariableState RemoveTag(VariableTag tag)
        {
            VariableTags.Remove(tag);

            return this;
        }

        public VariableState AddSyntaxNode(SyntaxNode node)
        {
            Node = node;
            return this;
        }
    }
}
