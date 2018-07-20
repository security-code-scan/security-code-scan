using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using static SecurityCodeScan.Analyzers.Taint.VariableTaint;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Define the state of variable regarding can it be trust, where does it come from.
    /// </summary>
    public class VariableState
    {
        public readonly List<VariableTag> VariableTags;

        public VariableTaint Taint { get; private set; }

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
        public VariableState(SyntaxNode node, VariableTaint taint = Unknown, object value = null)
        {
            Taint = taint;
            Value = null;
            if (Taint == Constant)
                Value = value;
            VariableTags = new List<VariableTag>();
            Node = node;
            PropertyStates = new Dictionary<string, VariableState>();
        }

        /// <summary>
        /// Merge two different states. State are merge if a data structure accept new input or 
        /// if values are concatenate.
        /// </summary>
        /// <param name="secondState"></param>
        /// <returns></returns>
        public void Merge(VariableState secondState)
        {
            if (Taint == Unset)
            {
                Taint = secondState.Taint;
            }
            else
            {
                switch (secondState.Taint)
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
                        if (Taint == Safe)
                        {
                            Taint = Safe;
                        }
                        else if (Taint == Constant)
                        {
                            Taint = Constant;
                            Value = secondState.Value;
                        }

                        break;
                    case Unset:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }

            if (secondState.Taint != Unset)
                Node = secondState.Node;

            // Searches through the new VariableState for new tags
            foreach (var newPropertyState in secondState.PropertyStates)
            {
                PropertyStates.Add(newPropertyState.Key, newPropertyState.Value);
            }

            // Searches through the new VariableState for new tags
            foreach (var newTag in secondState.VariableTags)
            {
                AddTag(newTag);
            }
        }

        public void MergeAndReplaceTaint(VariableState secondState)
        {
            if (secondState.Taint != Unset)
            {
                Taint = secondState.Taint;
                Value = Taint == Constant ? secondState.Value : null;
                Node = secondState.Node;
            }

            // Searches through the new VariableState for new tags
            foreach (var newPropertyState in secondState.PropertyStates)
            {
                PropertyStates.Add(newPropertyState.Key, newPropertyState.Value);
            }

            // Searches through the new VariableState for new tags
            foreach (var newTag in secondState.VariableTags)
            {
                AddTag(newTag);
            }
        }

        public VariableState MergeProperty(string identifier, VariableState secondState)
        {
            if (PropertyStates.ContainsKey(identifier))
                PropertyStates[identifier].MergeAndReplaceTaint(secondState);
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
