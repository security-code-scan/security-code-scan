using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using static SecurityCodeScan.Analyzers.Taint.VariableTaint;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Define the state of variable regarding can it be trust, where does it come from.
    /// 
    /// <code>struct</code> was chosen because the execution of the taint analysis will visited a lot.
    /// This may allow less heap allocation and less garbage collection.
    /// 
    /// <a href="https://msdn.microsoft.com/en-us/library/ms229017.aspx">Choosing Between Class and Struct</a>
    /// </summary>
    public struct VariableState
    {
        public VariableTaint Taint { get; }

        public List<VariableTag> Tags { get; }

        public SyntaxNode Node { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="taint">Initial state</param>
        public VariableState(SyntaxNode node, VariableTaint taint = Unknown, List<VariableTag> tags = null)
        {
            Taint = taint;
            Tags = tags ?? new List<VariableTag>();
            Node = node;
        }

        /// <summary>
        /// Merge two different states. State are merge if a data structure accept new input or 
        /// if values are concatenate.
        /// </summary>
        /// <param name="secondState"></param>
        /// <returns></returns>
        public VariableState Merge(VariableState secondState)
        {
            var newTaint = Taint;

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
                default:
                    throw new ArgumentOutOfRangeException();
            }

            // A new instance is made to prevent referencing the current VariableState's parameters
            var vs = new VariableState(Node, newTaint);

            // Searches through the current VariableState for unique tags
            foreach (var newTag in Tags)
            {
                vs.AddTag(newTag);
            }

            // Searches through the new VariableState for new tags
            foreach (var newTag in secondState.Tags)
            {
                vs.AddTag(newTag);
            }

            return vs;
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
            if (!Tags.Contains(tag))
            {
                Tags.Add(tag);
            }

            return this;
        }

        public VariableState AddSyntaxNode(SyntaxNode node)
        {
            Node = node;
            return this;
        }
    }
}
