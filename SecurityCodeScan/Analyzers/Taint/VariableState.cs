using System;
using System.Collections.Generic;
using System.Linq;
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
        public readonly List<VariableTag> VariableTags;

        public VariableTaint Taint { get; }

        /// <summary>
        /// Contains Value only is Taint is constant. Otherwise returns null
        /// </summary>
        public object Value { get; private set; }

        public List<Tag> Tags
        {
            get
            {
                var tags = new List<Tag>(VariableTags.Select(value => value.Tag));
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
        public VariableState(SyntaxNode node, VariableTaint taint = Unknown, object value = null, Dictionary<string, VariableState> propertyStates = null, List<VariableTag> tags = null)
        {
            Taint = taint;
            Value = null;
            if (Taint == Constant)
                Value = value;
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
            var newValue = Value;
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
                        {
                            newTaint = Safe;
                        }
                        else if (Taint == Constant)
                        {
                            newTaint = Constant;
                            newValue = secondState.Value;
                        }

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
            var vs = new VariableState(newNode, newTaint, newValue, PropertyStates, VariableTags);

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

        public VariableState MergeAndReplaceTaint(VariableState secondState)
        {
            var newNode = Node;
            var newValue = Value;
            var newTaint = Taint;

            if (secondState.Taint != Unset)
            {
                newTaint = secondState.Taint;
                newValue = newTaint == Constant ? secondState.Value : null;
                newNode = secondState.Node;
            }

            // A new instance is made to prevent referencing the current VariableState's parameters
            var vs = new VariableState(newNode, newTaint, newValue, PropertyStates, VariableTags);

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
                PropertyStates[identifier] = PropertyStates[identifier].MergeAndReplaceTaint(secondState);
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
            if (!VariableTags.Exists(t => t.Tag == tag.Tag))
            {
                VariableTags.Add(tag);
            }

            return this;
        }

        /// <summary>
        /// Will only add a new tag to the list if it is not already present in the list
        /// </summary>
        /// <param name="tag"></param>
        /// <param name="value"></param>
        /// <returns>A VariabeState with the updated list</returns>
        public VariableState AddTag(Tag tag, object value = null)
        {
            if (!VariableTags.Exists(t => t.Tag == tag))
            {
                VariableTags.Add(new VariableTag(tag, value));
            }

            return this;
        }

        public VariableState RemoveTag(Tag tag)
        {
            var tagToRemove = VariableTags.SingleOrDefault(t => t.Tag == tag);
            if(tagToRemove != null)
                VariableTags.Remove(tagToRemove);

            return this;
        }

        public IEnumerable<VariableTag> GetTags(Tag tag)
        {
            var result = new List<VariableTag>(VariableTags.Where(t => t.Tag == tag));
            foreach (var propertyState in PropertyStates.Values)
            {
                result.AddRange(propertyState.VariableTags.Where(t => t.Tag == tag));
            }

            return result;
        }
    }
}
