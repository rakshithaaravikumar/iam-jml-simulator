### **IAM Joiner-Mover-Leaver simulator**



A Python-based mini project that simulates common Identity and Access Management(IAM) lifecycle processes Joiner, Mover and Leaver (JML).



The project uses the dummy HR data to assign and remove access based on department roles, check Segregation of Duties(SOD)  conflicts , and identity residual access for terminated users.



Key Features:



* Joiner, Mover and Leaver lifecycle processing
* Role-Based Access Control(RBAC)
* Access provisioning and deprovisioning
* Segregation of Duties(SOD) validation
* Residual access detection
* Audit logging



Technologies:



* Python 3
* SQLite
* SQL
* CSV

No external Python packages are required.



How to Run:



py jml\_simulator.py



The program reads employee events from hr\_events.csv and create a local iam.db SQLite database.



Example Scenario:



A Finance employee is assigned Finance related access based on their role. If the employee moves to another department, the old role-based access is removed and the new access is assigned. When an employee leaves, their role-based access is removed. The project also simulates manually assigned access remaining after termination to demonstrate residual access detection.



Purpose:



This is a learning project created to practice Python development while applying IAM concepts such as JML, RBAC, SOD and access governance.

