package checks.regex;

import javax.validation.constraints.Email;

public class RedosCheck {

  @Email(regexp = "(.*-)*@.*") // Noncompliant [[sc=4;ec=9]] {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
  String email;

  void alwaysExponential(String str) {
    str.matches("(.*,)*?"); // Noncompliant [[sc=9;ec=16]] {{Make sure the regex used here, which is vulnerable to exponential runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.?,)*?"); // Noncompliant {{Make sure the regex used here, which is vulnerable to exponential runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(a|.a)*?"); // Noncompliant {{Make sure the regex used here, which is vulnerable to exponential runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*,)*X\\1"); // Noncompliant {{Make sure the regex used here, which is vulnerable to exponential runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*,)*\\1"); // False negative because RegexTreeHelper.intersects currently chokes on back references
  }

  void quadraticInJava9(String str) {
    str.matches("(.*,)*"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*,)*.*"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.split("(.*,)*X"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*,)*X"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*?,)+"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*?,){5,}"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("((.*,)*)*+"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("((.*,)*)?"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(?>(.*,)*)"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("((?>.*,)*)*"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches("(.*,)* (.*,)*"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}

    // False negatives because RegexTreeHelper.intersects currently chokes on boundaries:
    str.split("(.*,)*$");
    str.matches("(.*,)*$");
  }

  void alwaysQuadratic(String str) {
    str.matches("x*\\w*"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
    str.matches(".*.*X"); // Noncompliant {{Make sure the regex used here, which is vulnerable to quadratic runtime due to backtracking, cannot lead to denial of service.}}
  }

  void fixedInJava9(String str) {
    str.matches("(.?,)*X");
  }

  void compliant(String str) {
    str.split("(.*,)*");
    str.matches("(?s)(.*,)*.*");
    str.matches("(a|b)*");
    str.matches("(x*,){1,5}X");
    str.matches("((a|.a),)*");
    str.matches("(.*,)*[\\s\\S]*");
    str.matches("(?U)(.*,)*(.|\\s)*");
    str.matches("(x?,)?");
    str.matches("(?>.*,)*");
    str.matches("([^,]*+,)*");
    str.matches("(.*?,){5}");
    str.matches("(.*?,){1,5}");
    str.matches("([^,]*,)*");
    str.matches("(;?,)*");
    str.matches("(;*,)*");
    str.matches("(.*,)*("); // Rule is not applied to syntactically invalid regular expressions
  }

}
