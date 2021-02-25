SonarQube Java Custom Rules Plugin Template
=======

This example demonstrates how to write **Custom Rules** for SonarJava. Use the following command to build it without any dependency to the current project status:

```
mvn clean install -f pom_self_contained.xml -Dsonarqube.version=8.7.0.41497 -Dsonarjava.version=6.13.0.25138
```

To make sure it works for your configuration, don't forget to specify the `sonarqube.version` property corresponding to your SonarQube instance version, and the `sonarjava.version` corresponding to the version the Java Analyzer embedded in your SonarQube instance.

For more details about how to write custom rules, please refer to the official tutorial, [Writing Custom Java Rules 101](../CUSTOM_RULES_101.md).
