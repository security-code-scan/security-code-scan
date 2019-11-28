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
    internal class VariableState
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

        public static void Merge(Queue<KeyValuePair<VariableState, VariableState>> queue, Dictionary<VariableState, VariableState> otherToSelf)
        {
            while (queue.Any())
            {
                var correspondingVariables = queue.Dequeue();
                var otherVariable          = correspondingVariables.Key;
                var selfVariable           = correspondingVariables.Value;

                selfVariable.MergeTaint(otherVariable.Taint, otherVariable.Value);

                foreach (var otherProperty in otherVariable.PropertyStates)
                {
                    selfVariable.PropertyStates.TryGetValue(otherProperty.Key, out var selfProperty);
                    otherToSelf.TryGetValue(otherProperty.Value, out var correspondingSelfProperty);

                    if (selfProperty == null)
                    {
                        if (correspondingSelfProperty == null)
                        {
                            correspondingSelfProperty = new VariableState(otherProperty.Value.Node,
                                                                          otherProperty.Value.Taint,
                                                                          otherProperty.Value.Value);
                            otherToSelf.Add(otherProperty.Value, correspondingSelfProperty);
                        }

                        selfVariable.Properties.Add(otherProperty.Key, correspondingSelfProperty);
                    }
                    else if (correspondingSelfProperty != null)
                    {
                        continue;
                    }

                    queue.Enqueue(new KeyValuePair<VariableState, VariableState>(
                                      otherProperty.Value,
                                      selfVariable.PropertyStates[otherProperty.Key]));
                }
            }
        }

        /// <summary>
        /// Adds additional custom taint bit, or taint. Usually in post conditions.
        /// Differently from 'MergeTaint', bits are only added to existing ones.
        /// </summary>
        public void ApplyTaint(ulong newTaint)
        {
            var newVarTaint = (VariableTaint)newTaint;
            if (newVarTaint == Unset)
                return;

            if (newVarTaint == Safe || newVarTaint == Constant)
            {
                Taint = newVarTaint;
                return;
            }

            // only custom taint bits and Tainted are allowed
            if ((newVarTaint & (Safe | Tainted)) == 0)
                throw new ArgumentOutOfRangeException();

            if (Taint == Constant && (newVarTaint & Tainted) == 0)
                return; // sanitized const is still const

            Taint &= ~Constant;
            Taint |= newVarTaint;
        }

        /// <summary>
        /// Merges two taints (in concatenation case for example). The worst case wins.
        /// So tainted + sanitized gives tainted.
        /// </summary>
        public void MergeTaint(VariableTaint newTaint, object value = null)
        {
            if (newTaint == Unset)
                return;

            if (((Taint & Constant) != 0ul) && ((Taint & Safe) != 0ul))
                throw new ArgumentOutOfRangeException(); // precondition

            if (((newTaint & Constant) != 0ul) && ((newTaint & Safe) != 0ul))
                throw new ArgumentOutOfRangeException();

            if (Taint == Unset)
            {
                Taint = newTaint;
            }
            else if (Taint != Safe && newTaint != Safe &&
                     (Taint & (Unknown | Tainted)) != 0ul && ((Taint & Safe) != 0ul) &&
                     (newTaint & (Unknown | Tainted)) != 0ul && ((newTaint & Safe) != 0ul))
            {
                if (((Taint & Tainted) != 0ul) || ((newTaint & Tainted) != 0ul))
                    Taint = Tainted | (Taint & newTaint & Safe);
                else
                    Taint = Unknown | (Taint & newTaint & Safe);
            }
            else if ((Taint    == Constant && ((newTaint & Tainted) != 0ul) ||
                     (newTaint == Constant && ((Taint & Tainted) != 0ul))))
            {
                Taint = Tainted | ((Taint | newTaint) & Safe);
            }
            else if ((Taint == Constant && ((newTaint & Unknown) != 0ul) ||
                      (newTaint                                  == Constant && ((Taint & Unknown) != 0ul))))
            {
                Taint = Unknown | ((Taint | newTaint) & Safe);
            }
            else if ((Taint == Safe && ((newTaint & (Unknown | Tainted)) != 0ul)))
            {
                Taint = newTaint;
            }
            else if ((newTaint == Safe && ((Taint & (Unknown | Tainted)) != 0ul)))
            {
                //Taint = Taint;
            }
            else if(((newTaint & Tainted) != 0ul) || ((Taint & Tainted) != 0ul))
            {
                Taint = Tainted;
            }
            else if (((newTaint & Unknown) != 0ul) || ((Taint & Unknown) != 0ul))
            {
                Taint = Unknown;
            }
            else if (Taint == Constant && newTaint == Constant)
            {
                Taint = Constant;
            }
            else
            {
                Taint = Safe;
            }

            if (Taint == Constant)
                Value = value;
        }

        /// <summary>
        /// Merge two different states. Use it to merge two states when value is overridden.
        /// </summary>
        public void Replace(VariableState secondState)
        {
            if (secondState.Taint == Unset)
                return;

            Taint = secondState.Taint;
            Value = Taint == Constant ? secondState.Value : null;
            Node  = secondState.Node;

            Properties.Clear();
            foreach (var property in secondState.PropertyStates)
            {
                Properties.Add(property.Key, property.Value);
            }
        }

        public void AddOrMergeProperty(string identifier, VariableState secondState)
        {
            if (PropertyStates.ContainsKey(identifier))
            {
                PropertyStates[identifier].Replace(secondState);
                MergeTaint(secondState.Taint);
            }
            else
            {
                Properties.Add(identifier, secondState);
            }
        }

        public void AddProperty(string identifier, VariableState secondState)
        {
            Properties.Add(identifier, secondState);
        }

#if DEBUG
        public override string ToString()
        {
            var taintBits = Taint & Safe;
            if (taintBits != 0ul && taintBits != Safe)
                return $"{(Taint & ~Safe).ToString()} | {((ulong)taintBits).ToString()}";

            return Taint.ToString();
        }
#endif
    }
}
