using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace titun_windows_gui
{
    /// <summary>
    /// Configuration modal.
    /// 
    /// Compatible with the core program.
    /// </summary>
    public class Config
    {
        [Required, ValidateObject]
        public InterfaceConfig Interface { get; set; }

        [ValidateCollection]
        public List<PeerConfig> Peer { get; set; } = new List<PeerConfig>();
    }

    public class InterfaceConfig
    {
        [Ipv4Addr(ErrorMessage = "Address must be an IPv4 address")]
        public string Address { get; set; }
        [Range(0, 65536)]
        public uint? Mtu { get; set; }
        public List<string> Dns { get; set; } = new List<string>();
    }

    public class PeerConfig
    {
        [IpAddrPort(ErrorMessage = "Endpoint must be in the form of [IP:port]")]
        public string Endpoint { get; set; }
        [IpCidrList(ErrorMessage = "Allowed IPs must be in the form of IP or [IP/PREFIX_LENGTH]")]
        public List<string> AllowedIPs { get; set; } = new List<string>();
    }

    [AttributeUsage(AttributeTargets.Property |
  AttributeTargets.Field, AllowMultiple = false)]
    public class IpAddrPortAttribute : ValidationAttribute
    {
        public override bool IsValid(object value)
        {
            if (value == null)
            {
                return true;
            }
            try
            {
                var parts = (value as string).Split(':');
                if (parts.Length != 2)
                {
                    return false;
                }
                var a = IPAddress.Parse(parts[0]).AddressFamily;
                var p = ushort.Parse(parts[1]);
                return a == AddressFamily.InterNetwork || a == AddressFamily.InterNetworkV6;
            }
            catch (OverflowException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    [AttributeUsage(AttributeTargets.Property |
      AttributeTargets.Field, AllowMultiple = false)]
    public class Ipv4AddrAttribute : ValidationAttribute
    {
        public override bool IsValid(object value)
        {
            if (value == null)
            {
                return true;
            }
            try
            {
                var a = IPAddress.Parse(value as string);
                return a.AddressFamily == AddressFamily.InterNetwork;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    [AttributeUsage(AttributeTargets.Property |
      AttributeTargets.Field, AllowMultiple = false)]
    public class IpCidrListAttribute : ValidationAttribute
    {
        public override bool IsValid(object value)
        {
            if (!(value is List<string>))
            {
                return false;
            }
            foreach (var a in value as List<string>)
            {
                try
                {
                    var parts = a.Split('/');
                    if (parts.Length > 2)
                    {
                        return false;
                    }
                    var addr = IPAddress.Parse(parts[0]);
                    var famliy = addr.AddressFamily;
                    if (!(famliy == AddressFamily.InterNetwork || famliy == AddressFamily.InterNetworkV6))
                    {
                        return false;
                    }
                    if (parts.Length > 1)
                    {
                        var prefixLength = uint.Parse(parts[1]);
                        var maxPrefixLength = famliy == AddressFamily.InterNetwork ? 32 : 128;
                        if (prefixLength > maxPrefixLength)
                        {
                            return false;
                        }
                    }
                    return true;
                }
                catch (OverflowException)
                {
                    return false;
                }
                catch (FormatException)
                {
                    return false;
                }
            }
            return true;
        }
    }

    // Recursive validation.
    // These are from <https://github.com/jwcarroll/recursive-validator>, licensed under the UNLICENSE.
    public class ValidateCollectionAttribute : ValidationAttribute
    {
        public Type ValidationType { get; set; }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var collectionResults = new CompositeValidationResult(String.Format("Validation for {0} failed!",
                           validationContext.DisplayName));
            var enumerable = value as IEnumerable;

            var validators = GetValidators().ToList();

            if (enumerable != null)
            {
                var index = 0;

                foreach (var val in enumerable)
                {
                    var results = new List<ValidationResult>();
                    var context = new ValidationContext(val, validationContext.ServiceContainer, null);

                    if (ValidationType != null)
                    {
                        Validator.TryValidateValue(val, context, results, validators);
                    }
                    else
                    {
                        Validator.TryValidateObject(val, context, results, true);
                    }

                    if (results.Count != 0)
                    {
                        var compositeResults =
                           new CompositeValidationResult(String.Format("Validation for {0}[{1}] failed!",
                              validationContext.DisplayName, index));

                        results.ForEach(compositeResults.AddResult);

                        collectionResults.AddResult(compositeResults);
                    }

                    index++;
                }
            }

            if (collectionResults.Results.Any())
            {
                return collectionResults;
            }

            return ValidationResult.Success;
        }

        private IEnumerable<ValidationAttribute> GetValidators()
        {
            if (ValidationType == null) yield break;

            yield return (ValidationAttribute)Activator.CreateInstance(ValidationType);
        }
    }

    public class ValidateObjectAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var results = new List<ValidationResult>();
            var context = new ValidationContext(value, null, null);

            Validator.TryValidateObject(value, context, results, true);

            if (results.Count != 0)
            {
                var compositeResults = new CompositeValidationResult(String.Format("Validation for {0} failed!", validationContext.DisplayName));
                results.ForEach(compositeResults.AddResult);

                return compositeResults;
            }

            return ValidationResult.Success;
        }
    }

    public class CompositeValidationResult : ValidationResult
    {
        private readonly List<ValidationResult> _results = new List<ValidationResult>();

        public IEnumerable<ValidationResult> Results
        {
            get
            {
                return _results;
            }
        }

        public CompositeValidationResult(string errorMessage) : base(errorMessage) { }
        public CompositeValidationResult(string errorMessage, IEnumerable<string> memberNames) : base(errorMessage, memberNames) { }
        protected CompositeValidationResult(ValidationResult validationResult) : base(validationResult) { }

        public void AddResult(ValidationResult validationResult)
        {
            _results.Add(validationResult);
        }

        private string Indented(string input)
        {
            return string.Join("\n", input.Split('\n').Select(x => "    " + x));
        }

        public override string ToString()
        {
            var result = new StringBuilder();
            result.AppendLine(ErrorMessage);
            foreach (var r in Results)
            {
                result.AppendLine(Indented(r.ToString()));
            }
            return result.ToString();
        }
    }
}
