"""Question 4: access control matrix, ACL, C-list, policy checks, confused deputy, RBAC."""
from report_output import say

SUBJECTS = ["Arta", "Besnik", "Drita", "Ermal", "GradingService"]
OBJECTS = ["ExamQuestions", "SubmittedAnswers", "GradeDB", "AuditLog", "CoursePage"]
MATRIX = {
    "Arta":           {"SubmittedAnswers": "w", "CoursePage": "r"},
    "Besnik":         {"ExamQuestions": "r", "SubmittedAnswers": "r", "GradeDB": "rw", "CoursePage": "rw"},
    "Drita":          {"ExamQuestions": "rw", "SubmittedAnswers": "r", "GradeDB": "rw", "AuditLog": "r", "CoursePage": "rw"},
    "Ermal":          {"GradeDB": "r", "AuditLog": "r", "CoursePage": "r"},
    "GradingService": {"SubmittedAnswers": "r", "GradeDB": "rw", "AuditLog": "w"},
}


def rights(s, o):
    return MATRIX[s].get(o, "")


say("access control matrix (r = read, w = write, - = none)")
SHORT = {"ExamQuestions": "ExamQ", "SubmittedAnswers": "Answers", "GradeDB": "GradeDB", "AuditLog": "AuditLog", "CoursePage": "Course"}
say(f"{'':16s}" + "".join(f"{SHORT[o]:>10s}" for o in OBJECTS))
for s in SUBJECTS:
    say(f"{s:16s}" + "".join(f"{rights(s, o) or '-':>10s}" for o in OBJECTS))

say("\n(a) ACL of GradeDB (matrix stored by COLUMN)")
say("  GradeDB:", ", ".join(f"{s}: {rights(s, 'GradeDB')}" for s in SUBJECTS if rights(s, "GradeDB")))
say("\nC-list of Besnik (matrix stored by ROW)")
say("  Besnik:", ", ".join(f"{o}: {r}" for o, r in MATRIX["Besnik"].items()))

say("\n(b) automatic checks of the matrix")
findings = []
for s in SUBJECTS:
    if "w" in rights(s, "GradeDB") and "w" in rights(s, "AuditLog"):
        findings.append(f"{s} may write GradeDB AND AuditLog: it can change grades and rewrite the evidence")
for s in SUBJECTS:
    if s not in ("Drita", "GradingService") and "w" in rights(s, "GradeDB"):
        findings.append(f"{s} may write GradeDB although the role (TA) only needs to propose grades: "
                        f"no separation between grading and approval")
for s in ("Arta",):                                  # the only student in the matrix
    if "w" in rights(s, "SubmittedAnswers"):
        findings.append(f"{s} has w on the single object SubmittedAnswers: she can overwrite EVERYONE's answers, "
                        f"and the matrix cannot say 'only my own, only before the deadline'")
    if "r" not in rights(s, "GradeDB"):
        findings.append(f"{s} has no read right on GradeDB, so she cannot even see her own grade "
                        f"(the matrix cannot express 'only my own record')")
writers_log = [s for s in SUBJECTS if "w" in rights(s, "AuditLog")]
findings.append(f"the log has only 'w' (overwrite) and it is held by {writers_log}; there is no append-only right")
for i, f in enumerate(findings, 1):
    say(f"  {i}. {f}")

say("\n(c) confused deputy: GradingService exports a PDF to a file name chosen by the user")
GRADE_DB = "/db/grades.db"
OBJECT_OF_PATH = {GRADE_DB: "GradeDB", "/reports/arta.pdf": "ArtaReports"}


class FileSystem:
    def __init__(self):
        self.files = {GRADE_DB: "grade records for 1000 students", "/reports/arta.pdf": ""}

    def write(self, subject, path, data):
        obj = OBJECT_OF_PATH[path]
        allowed = "w" in rights(subject, obj) or (subject == "Arta" and obj == "ArtaReports")
        if not allowed:
            return f"DENIED  {subject} may not write {obj}"
        self.files[path] = data
        return f"allowed {subject} wrote {obj}"


fs = FileSystem()
say("  direct attack:   ", fs.write("Arta", GRADE_DB, "owned"))


def export_report_vulnerable(user, filename):
    """Checks the access rights of the SERVICE, not of the user: ambient authority."""
    return fs.write("GradingService", filename, f"PDF report requested by {user}")


say("  via the service: ", export_report_vulnerable("Arta", GRADE_DB))
say("  grade database now contains:", repr(fs.files[GRADE_DB]))

fs = FileSystem()


class Capability:
    def __init__(self, path):
        self.path = path


C_LIST = {"Arta": {"my_report": Capability("/reports/arta.pdf")}}   # Arta only holds capabilities she was given


def export_report_capability(user, cap_name):
    """The user must name a capability from her own C-list; the service writes exactly there."""
    cap = C_LIST[user].get(cap_name)
    if cap is None:
        return f"DENIED  {user} holds no capability named {cap_name!r}"
    fs.files[cap.path] = f"PDF report requested by {user}"
    return f"allowed wrote {cap.path}"


say("  capability version, Arta passes her own report capability:", export_report_capability("Arta", "my_report"))
say("  capability version, Arta asks for the grade database:     ", export_report_capability("Arta", "grade_db"))
say("  grade database now contains:", repr(fs.files[GRADE_DB]))

say("\n(d) RBAC for next semester")
students_n, tas_n, profs_n = 1000, 20, 30
users = students_n + tas_n + profs_n
roles = 3
say(f"  users = {students_n} + {tas_n} + {profs_n} = {users}")
say(f"  matrix cells (users x {len(OBJECTS)} objects) = {users * len(OBJECTS)}")
say(f"  RBAC: {roles} roles x {len(OBJECTS)} objects = {roles * len(OBJECTS)} permission cells + {users} user-role assignments")
say(f"  adding one student: 1 assignment (instead of {len(OBJECTS)} cells); "
    f"changing a rule for all students: 1 edit (instead of {students_n})")
