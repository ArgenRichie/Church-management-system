<?php
session_start();

// ── Database connection ────────────────────────────────────────────────────
$host = 'localhost';
$db   = 'church_db';
$user = 'root';
$pass = '';

$conn = new mysqli($host, $user, $pass);
if ($conn->connect_error) {
    die('<p style="font-family:sans-serif;padding:30px;color:red;">Database connection failed: ' . $conn->connect_error . '</p>');
}
$conn->query("CREATE DATABASE IF NOT EXISTS `$db`");
$conn->select_db($db);

// ── Create / migrate tables ────────────────────────────────────────────────
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin','staff') NOT NULL DEFAULT 'staff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

$conn->query("CREATE TABLE IF NOT EXISTS members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    phone VARCHAR(30),
    email VARCHAR(100),
    address TEXT,
    join_date DATE,
    birth_date DATE,
    hometown VARCHAR(150),
    membership_type VARCHAR(100),
    marital_status VARCHAR(50),
    other_roles VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

$conn->query("CREATE TABLE IF NOT EXISTS attendance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    member_id INT,
    service_date DATE NOT NULL,
    service_type VARCHAR(50),
    FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
)");

$conn->query("CREATE TABLE IF NOT EXISTS events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_name VARCHAR(150) NOT NULL,
    event_date DATE NOT NULL,
    event_time TIME,
    location VARCHAR(150),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

$conn->query("CREATE TABLE IF NOT EXISTS sermons (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    preacher VARCHAR(100),
    sermon_date DATE NOT NULL,
    scripture_reference VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

$conn->query("CREATE TABLE IF NOT EXISTS ministries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ministry_name VARCHAR(150) NOT NULL,
    leader VARCHAR(150),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

// ── Auth actions ───────────────────────────────────────────────────────────

// SIGNUP
if (isset($_POST['do_signup'])) {
    $name     = trim($_POST['signup_name']);
    $username = strtolower(trim($_POST['signup_username']));
    $pwd      = $_POST['signup_password'];
    $pwd2     = $_POST['signup_password2'];
    $role     = $_POST['signup_role'] ?? 'staff';

    if (empty($name) || empty($username) || empty($pwd)) {
        $auth_error = 'All fields are required.';
    } elseif (!preg_match('/^[a-z0-9_]+$/', $username)) {
        $auth_error = 'Username can only contain letters, numbers, and underscores.';
    } elseif ($pwd !== $pwd2) {
        $auth_error = 'Passwords do not match.';
    } elseif (strlen($pwd) < 6) {
        $auth_error = 'Password must be at least 6 characters.';
    } else {
        $check = $conn->prepare("SELECT id FROM users WHERE username=?");
        $check->bind_param('s', $username);
        $check->execute();
        $check->store_result();
        if ($check->num_rows > 0) {
            $auth_error = 'That username is already taken. Choose another.';
        } else {
            $hash = password_hash($pwd, PASSWORD_DEFAULT);
            $ins  = $conn->prepare("INSERT INTO users (full_name,username,password,role) VALUES (?,?,?,?)");
            $ins->bind_param('ssss', $name, $username, $hash, $role);
            $ins->execute();
            $auth_success = 'Account created! You can now log in.';
            $show_auth = 'login';
        }
    }
    if (!isset($show_auth)) $show_auth = 'signup';
}

// LOGIN
if (isset($_POST['do_login'])) {
    $username = strtolower(trim($_POST['login_username']));
    $pwd      = $_POST['login_password'];
    $stmt     = $conn->prepare("SELECT id,full_name,role,password FROM users WHERE username=?");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($row = $res->fetch_assoc()) {
        if (password_verify($pwd, $row['password'])) {
            $_SESSION['uid']   = $row['id'];
            $_SESSION['uname'] = $row['full_name'];
            $_SESSION['urole'] = $row['role'];
            header('Location: ?page=dashboard'); exit;
        } else {
            $auth_error = 'Incorrect password.';
        }
    } else {
        $auth_error = 'No account found with that username.';
    }
    $show_auth = 'login';
}

// LOGOUT
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ?auth=login'); exit;
}

// ── Guard: redirect to login if not logged in ──────────────────────────────
$auth_page = $_GET['auth'] ?? ($show_auth ?? null);
$is_logged_in = isset($_SESSION['uid']);

if (!$is_logged_in && !in_array($auth_page, ['login','signup'])) {
    $auth_page = 'login';
}

// ── Show auth pages (login / signup) before any app logic ─────────────────
if (!$is_logged_in):
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Christ Redeemer Church Int. Dome — <?= $auth_page === 'signup' ? 'Sign Up' : 'Login' ?></title>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Nunito:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{--red:#C0182A;--red-dark:#8B0F1E;--blue:#0D2B6B;--blue-mid:#1A3F9E;--white:#FFFFFF;--off-white:#F7F8FC;--cream:#EEF0F8;--text:#1A1A2E;--text-muted:#6B7280;--border:#D8DCF0;--radius:14px;}
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Nunito',sans-serif;background:linear-gradient(135deg,var(--blue) 0%,#0A1F52 50%,#1a0810 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
  .auth-wrap{width:100%;max-width:460px;}
  .auth-brand{text-align:center;margin-bottom:28px;}
  .cross-emblem{width:64px;height:64px;background:var(--red);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 14px;box-shadow:0 6px 20px rgba(192,24,42,0.45);}
  .auth-brand h1{font-family:'Cinzel',serif;color:#fff;font-size:1.1rem;font-weight:700;line-height:1.5;}
  .auth-brand p{color:rgba(255,255,255,0.35);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.12em;margin-top:4px;}
  .auth-card{background:var(--white);border-radius:var(--radius);padding:36px;box-shadow:0 20px 60px rgba(0,0,0,0.35);}
  .auth-card h2{font-family:'Cinzel',serif;font-size:1.3rem;color:var(--blue);margin-bottom:6px;font-weight:700;}
  .auth-card .subtitle{font-size:0.85rem;color:var(--text-muted);margin-bottom:28px;}
  .form-group{display:flex;flex-direction:column;gap:6px;margin-bottom:18px;}
  label{font-size:0.75rem;font-weight:700;color:var(--blue);text-transform:uppercase;letter-spacing:0.06em;}
  input[type="text"],input[type="email"],input[type="password"],select{width:100%;padding:11px 14px;border:1.5px solid var(--border);border-radius:9px;font-size:0.9rem;font-family:'Nunito',sans-serif;color:var(--text);background:var(--off-white);outline:none;transition:border-color 0.2s;}
  input:focus,select:focus{border-color:var(--blue-mid);background:#fff;}
  .btn-auth{width:100%;padding:13px;background:var(--red);color:#fff;border:none;border-radius:9px;font-size:1rem;font-family:'Cinzel',serif;font-weight:700;cursor:pointer;letter-spacing:0.04em;transition:background 0.2s;margin-top:6px;}
  .btn-auth:hover{background:var(--red-dark);}
  .auth-switch{text-align:center;margin-top:20px;font-size:0.85rem;color:var(--text-muted);}
  .auth-switch a{color:var(--blue-mid);font-weight:700;text-decoration:none;}
  .auth-switch a:hover{text-decoration:underline;}
  .alert-error{background:#fde8eb;border:1px solid #f5c6cb;color:var(--red-dark);padding:12px 16px;border-radius:9px;font-size:0.88rem;font-weight:600;margin-bottom:20px;}
  .alert-success{background:#d4edda;border:1px solid #a8d5bc;color:#1a6b3a;padding:12px 16px;border-radius:9px;font-size:0.88rem;font-weight:600;margin-bottom:20px;}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
  .verse{text-align:center;margin-top:24px;font-size:0.75rem;font-style:italic;color:rgba(255,255,255,0.3);}
</style>
</head>
<body>
<div class="auth-wrap">
  <div class="auth-brand">
    <div class="cross-emblem">✝</div>
    <h1>Christ Redeemer Church<br>International, Dome</h1>
    <p>Management System</p>
  </div>

  <div class="auth-card">
    <?php if (isset($auth_error)): ?>
      <div class="alert-error">⚠️ <?= htmlspecialchars($auth_error) ?></div>
    <?php endif; ?>
    <?php if (isset($auth_success)): ?>
      <div class="alert-success">✅ <?= htmlspecialchars($auth_success) ?></div>
    <?php endif; ?>

    <?php if ($auth_page === 'signup'): ?>
      <!-- ── SIGNUP FORM ── -->
      <h2>Create Account</h2>
      <p class="subtitle">Register a new staff or admin account</p>
      <form method="POST">
        <div class="form-group">
          <label>Full Name *</label>
          <input type="text" name="signup_name" required placeholder="e.g. Kofi Mensah" value="<?= htmlspecialchars($_POST['signup_name'] ?? '') ?>">
        </div>
        <div class="form-group">
          <label>Username *</label>
          <input type="text" name="signup_username" required placeholder="e.g. kofi_admin" value="<?= htmlspecialchars($_POST['signup_username'] ?? '') ?>">
          <small style="color:var(--text-muted);font-size:0.75rem;">Letters, numbers, and underscores only. No spaces.</small>
        </div>
        <div class="two-col">
          <div class="form-group">
            <label>Password *</label>
            <input type="password" name="signup_password" required placeholder="Min. 6 characters">
          </div>
          <div class="form-group">
            <label>Confirm Password *</label>
            <input type="password" name="signup_password2" required placeholder="Repeat password">
          </div>
        </div>
        <div class="form-group">
          <label>Role</label>
          <select name="signup_role">
            <option value="staff">Staff</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <button type="submit" name="do_signup" class="btn-auth">Create Account</button>
      </form>
      <div class="auth-switch">Already have an account? <a href="?auth=login">Sign In</a></div>

    <?php else: ?>
      <!-- ── LOGIN FORM ── -->
      <h2>Welcome Back</h2>
      <p class="subtitle">Sign in to manage your congregation</p>
      <form method="POST">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="login_username" required placeholder="Your username" value="<?= htmlspecialchars($_POST['login_username'] ?? '') ?>">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="login_password" required placeholder="Your password">
        </div>
        <button type="submit" name="do_login" class="btn-auth">Sign In</button>
      </form>
      <div class="auth-switch">Don't have an account? <a href="?auth=signup">Sign Up</a></div>
    <?php endif; ?>
  </div>

  <div class="verse">"I can do all things through Christ who strengthens me." — Philippians 4:13</div>
</div>
</body>
</html>
<?php
// Stop here — do not render the app
exit;
endif;

// ══════════════════════════════════════════════════════════════════════════
// APP LOGIC — only runs if logged in
// ══════════════════════════════════════════════════════════════════════════

// ── Handle all actions ─────────────────────────────────────────────────────
$message = '';

// MEMBERS
if (isset($_POST['add_member'])) {
    $stmt = $conn->prepare("INSERT INTO members (full_name,phone,email,address,join_date,birth_date,hometown,membership_type,marital_status,other_roles) VALUES (?,?,?,?,?,?,?,?,?,?)");
    $stmt->bind_param('ssssssssss',$_POST['full_name'],$_POST['phone'],$_POST['email'],$_POST['address'],$_POST['join_date'],$_POST['birth_date'],$_POST['hometown'],$_POST['membership_type'],$_POST['marital_status'],$_POST['other_roles']);
    $stmt->execute();
    header('Location: ?page=members&msg='.urlencode('Member added successfully!')); exit;
}
if (isset($_POST['edit_member'])) {
    $id = intval($_POST['member_id']);
    $stmt = $conn->prepare("UPDATE members SET full_name=?,phone=?,email=?,address=?,join_date=?,birth_date=?,hometown=?,membership_type=?,marital_status=?,other_roles=? WHERE id=?");
    $stmt->bind_param('ssssssssssi',$_POST['full_name'],$_POST['phone'],$_POST['email'],$_POST['address'],$_POST['join_date'],$_POST['birth_date'],$_POST['hometown'],$_POST['membership_type'],$_POST['marital_status'],$_POST['other_roles'],$id);
    $stmt->execute();
    header('Location: ?page=members&msg='.urlencode('Member updated successfully!')); exit;
}
if (isset($_POST['delete_member'])) {
    $id = intval($_POST['delete_member']);
    $conn->query("DELETE FROM members WHERE id=$id");
    header('Location: ?page=members&msg='.urlencode('Member deleted.')); exit;
}

// ATTENDANCE
if (isset($_POST['add_attendance'])) {
    $mid=$conn->real_escape_string(intval($_POST['member_id']));
    $sd=$conn->real_escape_string($_POST['service_date']);
    $st=$conn->real_escape_string($_POST['service_type']);
    $conn->query("INSERT INTO attendance (member_id,service_date,service_type) VALUES ($mid,'$sd','$st')");
    $message='Attendance recorded!';
}

// EVENTS
if (isset($_POST['add_event'])) {
    $stmt=$conn->prepare("INSERT INTO events (event_name,event_date,event_time,location,description) VALUES (?,?,?,?,?)");
    $stmt->bind_param('sssss',$_POST['event_name'],$_POST['event_date'],$_POST['event_time'],$_POST['location'],$_POST['description']);
    $stmt->execute();
    header('Location: ?page=events&msg='.urlencode('Event added!')); exit;
}
if (isset($_POST['edit_event'])) {
    $id=intval($_POST['event_id']);
    $stmt=$conn->prepare("UPDATE events SET event_name=?,event_date=?,event_time=?,location=?,description=? WHERE id=?");
    $stmt->bind_param('sssssi',$_POST['event_name'],$_POST['event_date'],$_POST['event_time'],$_POST['location'],$_POST['description'],$id);
    $stmt->execute();
    header('Location: ?page=events&msg='.urlencode('Event updated!')); exit;
}
if (isset($_POST['delete_event'])) {
    $id=intval($_POST['delete_event']);
    $conn->query("DELETE FROM events WHERE id=$id");
    header('Location: ?page=events&msg='.urlencode('Event deleted.')); exit;
}

// SERMONS
if (isset($_POST['add_sermon'])) {
    $stmt=$conn->prepare("INSERT INTO sermons (title,preacher,sermon_date,scripture_reference,notes) VALUES (?,?,?,?,?)");
    $stmt->bind_param('sssss',$_POST['title'],$_POST['preacher'],$_POST['sermon_date'],$_POST['scripture_reference'],$_POST['notes']);
    $stmt->execute();
    header('Location: ?page=sermons&msg='.urlencode('Sermon saved!')); exit;
}
if (isset($_POST['edit_sermon'])) {
    $id=intval($_POST['sermon_id']);
    $stmt=$conn->prepare("UPDATE sermons SET title=?,preacher=?,sermon_date=?,scripture_reference=?,notes=? WHERE id=?");
    $stmt->bind_param('sssssi',$_POST['title'],$_POST['preacher'],$_POST['sermon_date'],$_POST['scripture_reference'],$_POST['notes'],$id);
    $stmt->execute();
    header('Location: ?page=sermons&msg='.urlencode('Sermon updated!')); exit;
}
if (isset($_POST['delete_sermon'])) {
    $id=intval($_POST['delete_sermon']);
    $conn->query("DELETE FROM sermons WHERE id=$id");
    header('Location: ?page=sermons&msg='.urlencode('Sermon deleted.')); exit;
}

// MINISTRIES
if (isset($_POST['add_ministry'])) {
    $stmt=$conn->prepare("INSERT INTO ministries (ministry_name,leader,description) VALUES (?,?,?)");
    $stmt->bind_param('sss',$_POST['ministry_name'],$_POST['leader'],$_POST['description']);
    $stmt->execute();
    header('Location: ?page=ministries&msg='.urlencode('Ministry added!')); exit;
}
if (isset($_POST['edit_ministry'])) {
    $id=intval($_POST['ministry_id']);
    $stmt=$conn->prepare("UPDATE ministries SET ministry_name=?,leader=?,description=? WHERE id=?");
    $stmt->bind_param('sssi',$_POST['ministry_name'],$_POST['leader'],$_POST['description'],$id);
    $stmt->execute();
    header('Location: ?page=ministries&msg='.urlencode('Ministry updated!')); exit;
}
if (isset($_POST['delete_ministry'])) {
    $id=intval($_POST['delete_ministry']);
    $conn->query("DELETE FROM ministries WHERE id=$id");
    header('Location: ?page=ministries&msg='.urlencode('Ministry deleted.')); exit;
}

// ── Page setup ─────────────────────────────────────────────────────────────
$page    = $_GET['page'] ?? 'dashboard';
$message = isset($_GET['msg']) ? htmlspecialchars($_GET['msg']) : $message;

$total_members    = $conn->query("SELECT COUNT(*) c FROM members")->fetch_assoc()['c'];
$total_events     = $conn->query("SELECT COUNT(*) c FROM events")->fetch_assoc()['c'];
$total_sermons    = $conn->query("SELECT COUNT(*) c FROM sermons")->fetch_assoc()['c'];
$total_ministries = $conn->query("SELECT COUNT(*) c FROM ministries")->fetch_assoc()['c'];
$this_month_att   = $conn->query("SELECT COUNT(*) c FROM attendance WHERE MONTH(service_date)=MONTH(NOW()) AND YEAR(service_date)=YEAR(NOW())")->fetch_assoc()['c'];

$search=$_GET['search']??'';
$se=$conn->real_escape_string($search);
$search_sql=$search?"WHERE full_name LIKE '%$se%' OR email LIKE '%$se%'":'';

$edit_member=$edit_event=$edit_sermon=$edit_ministry=null;
if($page==='edit_member'   &&isset($_GET['id'])){$id=intval($_GET['id']);$edit_member   =$conn->query("SELECT * FROM members    WHERE id=$id")->fetch_assoc();if(!$edit_member)   {header('Location: ?page=members');exit;}}
if($page==='edit_event'    &&isset($_GET['id'])){$id=intval($_GET['id']);$edit_event    =$conn->query("SELECT * FROM events     WHERE id=$id")->fetch_assoc();if(!$edit_event)    {header('Location: ?page=events');exit;}}
if($page==='edit_sermon'   &&isset($_GET['id'])){$id=intval($_GET['id']);$edit_sermon   =$conn->query("SELECT * FROM sermons    WHERE id=$id")->fetch_assoc();if(!$edit_sermon)   {header('Location: ?page=sermons');exit;}}
if($page==='edit_ministry' &&isset($_GET['id'])){$id=intval($_GET['id']);$edit_ministry =$conn->query("SELECT * FROM ministries WHERE id=$id")->fetch_assoc();if(!$edit_ministry) {header('Location: ?page=ministries');exit;}}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Christ Redeemer Church Int. Dome</title>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Nunito:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{--red:#C0182A;--red-dark:#8B0F1E;--red-light:#E8304A;--blue:#0D2B6B;--blue-mid:#1A3F9E;--blue-light:#2755CC;--white:#FFFFFF;--off-white:#F7F8FC;--cream:#EEF0F8;--text:#1A1A2E;--text-muted:#6B7280;--border:#D8DCF0;--sidebar-w:260px;--radius:12px;--shadow:0 4px 20px rgba(13,43,107,0.10);}
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Nunito',sans-serif;background:var(--off-white);color:var(--text);min-height:100vh;display:flex;}
  .sidebar{width:var(--sidebar-w);background:linear-gradient(180deg,var(--blue) 0%,#0A1F52 100%);min-height:100vh;position:fixed;top:0;left:0;display:flex;flex-direction:column;z-index:100;}
  .sidebar-logo{padding:28px 20px 22px;border-bottom:1px solid rgba(255,255,255,0.1);text-align:center;}
  .cross-emblem{width:52px;height:52px;background:var(--red);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;margin:0 auto 10px;box-shadow:0 4px 12px rgba(192,24,42,0.4);}
  .sidebar-logo h1{font-family:'Cinzel',serif;color:var(--white);font-size:0.82rem;font-weight:700;line-height:1.5;}
  .sidebar-logo p{color:rgba(255,255,255,0.35);font-size:0.68rem;letter-spacing:0.1em;text-transform:uppercase;margin-top:4px;}
  .sidebar-nav{flex:1;padding:16px 0;}
  .nav-section{padding:14px 20px 4px;font-size:0.6rem;letter-spacing:0.14em;text-transform:uppercase;color:rgba(255,255,255,0.28);font-weight:700;}
  .nav-link{display:flex;align-items:center;gap:12px;padding:11px 20px;color:rgba(255,255,255,0.6);text-decoration:none;font-size:0.88rem;font-weight:500;transition:all 0.2s;border-left:3px solid transparent;margin:1px 0;}
  .nav-link:hover{color:var(--white);background:rgba(255,255,255,0.06);}
  .nav-link.active{color:var(--white);background:rgba(192,24,42,0.25);border-left-color:var(--red-light);font-weight:700;}
  .nav-link .icon{font-size:1rem;width:20px;text-align:center;}
  .sidebar-footer{padding:16px 20px;border-top:1px solid rgba(255,255,255,0.07);font-size:0.72rem;color:rgba(255,255,255,0.35);text-align:center;}
  .sidebar-footer a{color:rgba(255,255,255,0.5);text-decoration:none;font-weight:700;}
  .sidebar-footer a:hover{color:#fff;}
  .main{margin-left:var(--sidebar-w);flex:1;display:flex;flex-direction:column;min-height:100vh;}
  .topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 36px;height:66px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50;box-shadow:0 2px 8px rgba(13,43,107,0.06);}
  .topbar-left{display:flex;align-items:center;gap:14px;}
  .topbar-flag{display:flex;gap:3px;align-items:center;}
  .flag-stripe{width:6px;height:28px;border-radius:3px;}
  .topbar-title{font-family:'Cinzel',serif;font-size:1.1rem;color:var(--blue);font-weight:600;}
  .topbar-right{display:flex;align-items:center;gap:14px;}
  .topbar-user{font-size:0.82rem;color:var(--text-muted);background:var(--cream);padding:6px 14px;border-radius:20px;font-weight:600;}
  .topbar-date{font-size:0.8rem;color:var(--text-muted);background:var(--cream);padding:6px 14px;border-radius:20px;font-weight:500;}
  .btn-logout{background:transparent;color:var(--red);border:2px solid #f5c6cb;padding:6px 14px;font-size:0.78rem;border-radius:8px;font-family:'Nunito',sans-serif;font-weight:700;cursor:pointer;text-decoration:none;transition:all .2s;}
  .btn-logout:hover{background:var(--red);color:#fff;border-color:var(--red);}
  .content{padding:32px 36px;flex:1;}
  .alert{background:linear-gradient(135deg,#dff0e8,#c8e6d4);border:1px solid #a8d5bc;color:#1a6b3a;padding:14px 20px;border-radius:var(--radius);margin-bottom:24px;font-weight:600;display:flex;align-items:center;gap:10px;}
  .page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;flex-wrap:wrap;gap:12px;}
  .page-header h2{font-family:'Cinzel',serif;font-size:1.5rem;color:var(--blue);font-weight:700;}
  .btn{display:inline-flex;align-items:center;gap:6px;padding:10px 22px;border-radius:8px;font-size:0.875rem;font-weight:700;cursor:pointer;text-decoration:none;border:2px solid transparent;transition:all 0.2s;font-family:'Nunito',sans-serif;}
  .btn-red{background:var(--red);color:var(--white);border-color:var(--red);}
  .btn-red:hover{background:var(--red-dark);border-color:var(--red-dark);}
  .btn-blue{background:var(--blue);color:var(--white);border-color:var(--blue);}
  .btn-blue:hover{background:var(--blue-mid);}
  .btn-outline{background:transparent;color:var(--blue);border-color:var(--border);}
  .btn-outline:hover{border-color:var(--blue);background:var(--cream);}
  .btn-sm{padding:7px 16px;font-size:0.8rem;}
  .action-group{display:flex;gap:6px;align-items:center;}
  .btn-edit{background:transparent;color:var(--blue-mid);border:2px solid #b8caff;padding:6px 14px;font-size:0.78rem;border-radius:8px;font-family:'Nunito',sans-serif;font-weight:700;cursor:pointer;transition:all .2s;text-decoration:none;display:inline-flex;align-items:center;gap:4px;}
  .btn-edit:hover{background:var(--blue-mid);color:white;border-color:var(--blue-mid);}
  .btn-del{background:transparent;color:var(--red);border:2px solid #f5c6cb;padding:6px 14px;font-size:0.78rem;border-radius:8px;font-family:'Nunito',sans-serif;font-weight:700;cursor:pointer;transition:all .2s;}
  .btn-del:hover{background:var(--red);color:white;border-color:var(--red);}
  form.del-form{display:inline;}
  .welcome-card{background:linear-gradient(135deg,var(--blue) 0%,var(--blue-mid) 60%,var(--red-dark) 100%);border-radius:var(--radius);padding:32px 36px;color:var(--white);margin-bottom:28px;position:relative;overflow:hidden;}
  .welcome-card::before{content:'✝';position:absolute;right:30px;top:50%;transform:translateY(-50%);font-size:110px;opacity:0.05;font-family:'Cinzel',serif;}
  .welcome-card h2{font-family:'Cinzel',serif;font-size:1.5rem;margin-bottom:6px;}
  .welcome-card p{opacity:0.75;font-size:0.9rem;max-width:500px;}
  .welcome-card .verse{margin-top:12px;font-style:italic;font-size:0.82rem;opacity:0.55;border-top:1px solid rgba(255,255,255,0.15);padding-top:10px;}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:20px;margin-bottom:28px;}
  .stat-card{background:var(--white);border-radius:var(--radius);padding:22px 24px;box-shadow:var(--shadow);display:flex;align-items:center;gap:18px;border-left:5px solid var(--blue);}
  .stat-card.red-acc{border-left-color:var(--red);}
  .stat-card.mid-acc{border-left-color:var(--blue-light);}
  .stat-icon{width:50px;height:50px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.4rem;flex-shrink:0;}
  .stat-icon.blue-bg{background:rgba(13,43,107,0.08);}
  .stat-icon.red-bg{background:rgba(192,24,42,0.08);}
  .stat-num{font-family:'Cinzel',serif;font-size:2rem;font-weight:700;color:var(--blue);line-height:1;}
  .stat-label{font-size:0.75rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-top:4px;}
  .table-wrap{background:var(--white);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;}
  .table-toolbar{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
  .search-box{display:flex;align-items:center;gap:8px;background:var(--cream);border:1.5px solid var(--border);border-radius:8px;padding:8px 14px;}
  .search-box input{border:none;background:transparent;outline:none;font-size:0.88rem;font-family:inherit;min-width:200px;color:var(--text);}
  table{width:100%;border-collapse:collapse;}
  thead tr{background:linear-gradient(90deg,var(--blue),var(--blue-mid));}
  thead th{padding:14px 20px;text-align:left;font-size:0.72rem;font-weight:700;color:rgba(255,255,255,0.8);text-transform:uppercase;letter-spacing:0.09em;}
  tbody tr{border-bottom:1px solid var(--border);transition:background 0.15s;}
  tbody tr:hover{background:var(--cream);}
  tbody tr:last-child{border-bottom:none;}
  td{padding:13px 20px;font-size:0.88rem;color:var(--text);vertical-align:middle;}
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.7rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;}
  .badge-red{background:#fde8eb;color:var(--red-dark);}
  .badge-blue{background:#dce8ff;color:var(--blue);}
  .badge-green{background:#d4edda;color:#1b5e34;}
  .badge-gray{background:#f1f1f1;color:#555;}
  .form-card{background:var(--white);border-radius:var(--radius);box-shadow:var(--shadow);padding:32px;max-width:760px;}
  .form-section{font-family:'Cinzel',serif;font-size:0.85rem;color:var(--blue);border-bottom:2px solid var(--cream);padding-bottom:6px;margin:20px 0 14px;letter-spacing:0.04em;}
  .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
  .form-group{display:flex;flex-direction:column;gap:6px;}
  .form-group.full{grid-column:1/-1;}
  label{font-size:0.78rem;font-weight:700;color:var(--blue);text-transform:uppercase;letter-spacing:0.06em;}
  input[type="text"],input[type="email"],input[type="tel"],input[type="date"],input[type="time"],input[type="month"],select,textarea{width:100%;padding:10px 14px;border:1.5px solid var(--border);border-radius:8px;font-size:0.9rem;font-family:'Nunito',sans-serif;color:var(--text);background:var(--off-white);outline:none;transition:border-color 0.2s,background 0.2s;}
  input:focus,select:focus,textarea:focus{border-color:var(--blue-light);background:var(--white);}
  textarea{resize:vertical;min-height:100px;}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:28px;}
  .card{background:var(--white);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;}
  .card-title{font-family:'Cinzel',serif;font-size:1rem;color:var(--blue);margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid var(--cream);}
  .event-item{display:flex;gap:14px;padding:10px 0;border-bottom:1px solid var(--border);align-items:flex-start;}
  .event-item:last-child{border-bottom:none;}
  .event-date-box{background:linear-gradient(135deg,var(--red),var(--red-dark));color:var(--white);border-radius:10px;padding:8px 10px;text-align:center;min-width:50px;box-shadow:0 3px 10px rgba(192,24,42,0.3);}
  .event-date-box .day{font-size:1.2rem;font-weight:700;font-family:'Cinzel',serif;line-height:1;}
  .event-date-box .mon{font-size:0.6rem;text-transform:uppercase;letter-spacing:0.08em;opacity:0.85;}
  .event-info h4{font-size:0.9rem;font-weight:700;color:var(--blue);}
  .event-info p{font-size:0.78rem;color:var(--text-muted);margin-top:2px;}
  @media(max-width:960px){
    .sidebar{width:64px;}.sidebar-logo h1,.sidebar-logo p,.nav-link span,.nav-section,.cross-emblem{display:none;}
    .nav-link{justify-content:center;padding:14px;}.main{margin-left:64px;}.content{padding:20px;}
    .form-grid{grid-template-columns:1fr;}.form-group.full{grid-column:1;}.two-col{grid-template-columns:1fr;}.topbar{padding:0 20px;}
  }
</style>
</head>
<body>

<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="cross-emblem">✝</div>
    <h1>Christ Redeemer Church<br>International, Dome</h1>
    <p>Management System</p>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <a href="?page=dashboard" class="nav-link <?= $page==='dashboard'?'active':'' ?>"><span class="icon">🏠</span><span>Dashboard</span></a>
    <div class="nav-section">People</div>
    <a href="?page=members"    class="nav-link <?= in_array($page,['members','add_member','edit_member'])?'active':'' ?>"><span class="icon">👥</span><span>Members</span></a>
    <a href="?page=attendance" class="nav-link <?= in_array($page,['attendance','add_attendance'])?'active':'' ?>"><span class="icon">📋</span><span>Attendance</span></a>
    <div class="nav-section">Church</div>
    <a href="?page=events"     class="nav-link <?= in_array($page,['events','add_event','edit_event'])?'active':'' ?>"><span class="icon">📅</span><span>Events</span></a>
    <a href="?page=sermons"    class="nav-link <?= in_array($page,['sermons','add_sermon','edit_sermon'])?'active':'' ?>"><span class="icon">📖</span><span>Sermons</span></a>
    <a href="?page=ministries" class="nav-link <?= in_array($page,['ministries','add_ministry','edit_ministry'])?'active':'' ?>"><span class="icon">🙏</span><span>Ministries</span></a>
  </nav>
  <div class="sidebar-footer">
    © <?= date('Y') ?> CRCI Dome<br>
    <a href="?logout=1">🚪 Sign Out</a>
  </div>
</aside>

<div class="main">
  <header class="topbar">
    <div class="topbar-left">
      <div class="topbar-flag">
        <div class="flag-stripe" style="background:var(--red);"></div>
        <div class="flag-stripe" style="background:var(--white);border:1px solid var(--border);"></div>
        <div class="flag-stripe" style="background:var(--blue);"></div>
      </div>
      <div class="topbar-title"><?php
        $titles=['dashboard'=>'Dashboard','members'=>'Members','add_member'=>'Add Member','edit_member'=>'Edit Member',
          'attendance'=>'Attendance','add_attendance'=>'Record Attendance',
          'events'=>'Events','add_event'=>'Add Event','edit_event'=>'Edit Event',
          'sermons'=>'Sermons','add_sermon'=>'Add Sermon','edit_sermon'=>'Edit Sermon',
          'ministries'=>'Ministries','add_ministry'=>'Add Ministry','edit_ministry'=>'Edit Ministry'];
        echo $titles[$page]??'Dashboard';
      ?></div>
    </div>
    <div class="topbar-right">
      <div class="topbar-user">👤 <?= htmlspecialchars($_SESSION['uname']) ?> <span class="badge badge-blue" style="font-size:0.6rem;"><?= htmlspecialchars($_SESSION['urole']) ?></span></div>
      <div class="topbar-date">📅 <?= date('l, F j, Y') ?></div>
      <a href="?logout=1" class="btn-logout">🚪 Logout</a>
    </div>
  </header>

  <div class="content">
    <?php if($message):?><div class="alert">✅ <?= $message ?></div><?php endif;?>

    <?php /* ═══ DASHBOARD ═══ */ if($page==='dashboard'): ?>
      <div class="welcome-card">
        <h2>Welcome, <?= htmlspecialchars(explode(' ', $_SESSION['uname'])[0]) ?> 🙏</h2>
        <p>Christ Redeemer Church International, Dome — managing your congregation with faith and excellence.</p>
        <div class="verse">"For where two or three gather in my name, there am I with them." — Matthew 18:20</div>
      </div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-icon blue-bg">👥</div><div><div class="stat-num"><?=$total_members?></div><div class="stat-label">Total Members</div></div></div>
        <div class="stat-card red-acc"><div class="stat-icon red-bg">📋</div><div><div class="stat-num"><?=$this_month_att?></div><div class="stat-label">Attendance This Month</div></div></div>
        <div class="stat-card mid-acc"><div class="stat-icon blue-bg">📅</div><div><div class="stat-num"><?=$total_events?></div><div class="stat-label">Events</div></div></div>
        <div class="stat-card red-acc"><div class="stat-icon red-bg">📖</div><div><div class="stat-num"><?=$total_sermons?></div><div class="stat-label">Sermons</div></div></div>
        <div class="stat-card"><div class="stat-icon blue-bg">🙏</div><div><div class="stat-num"><?=$total_ministries?></div><div class="stat-label">Ministries</div></div></div>
      </div>
      <div class="two-col">
        <div class="card">
          <div class="card-title">📅 Upcoming Events</div>
          <?php $ev=$conn->query("SELECT * FROM events WHERE event_date>=CURDATE() ORDER BY event_date ASC LIMIT 5");$ec=0;
            while($e=$ev->fetch_assoc()){$ec++;$dt=new DateTime($e['event_date']);?>
          <div class="event-item">
            <div class="event-date-box"><div class="day"><?=$dt->format('d')?></div><div class="mon"><?=$dt->format('M')?></div></div>
            <div class="event-info"><h4><?=htmlspecialchars($e['event_name'])?></h4><p><?=htmlspecialchars($e['location']?:'Location TBD')?><?=$e['event_time']?' · '.date('g:i A',strtotime($e['event_time'])):''?></p></div>
          </div>
          <?php }if(!$ec):?><p style="color:var(--text-muted);font-size:.85rem;text-align:center;padding:20px 0;">No upcoming events</p><?php endif;?>
          <div style="margin-top:16px;"><a href="?page=add_event" class="btn btn-red btn-sm">+ Add Event</a></div>
        </div>
        <div class="card">
          <div class="card-title">👥 Recent Members</div>
          <?php $rm=$conn->query("SELECT * FROM members ORDER BY created_at DESC LIMIT 5");$rmc=0;
            while($m=$rm->fetch_assoc()){$rmc++;?>
          <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);">
            <div><div style="font-weight:700;font-size:.9rem;"><?=htmlspecialchars($m['full_name'])?></div>
            <div style="font-size:.78rem;color:var(--text-muted);"><?=htmlspecialchars($m['email']?:($m['phone']?:'No contact'))?></div></div>
            <span class="badge badge-blue"><?=htmlspecialchars($m['membership_type']?:'Member')?></span>
          </div>
          <?php }if(!$rmc):?><p style="color:var(--text-muted);font-size:.85rem;text-align:center;padding:20px 0;">No members yet</p><?php endif;?>
          <div style="margin-top:16px;"><a href="?page=add_member" class="btn btn-blue btn-sm">+ Add Member</a></div>
        </div>
      </div>

    <?php /* ═══ MEMBERS LIST ═══ */ elseif($page==='members'): ?>
      <div class="page-header"><h2>Church Members</h2><a href="?page=add_member" class="btn btn-red">+ Add Member</a></div>
      <div class="table-wrap">
        <div class="table-toolbar">
          <form method="GET" style="display:flex;gap:8px;align-items:center;">
            <input type="hidden" name="page" value="members">
            <div class="search-box">🔍<input type="text" name="search" placeholder="Search name or email..." value="<?=htmlspecialchars($search)?>"></div>
            <button type="submit" class="btn btn-blue btn-sm">Search</button>
            <?php if($search):?><a href="?page=members" class="btn btn-outline btn-sm">Clear</a><?php endif;?>
          </form>
          <span style="font-size:.8rem;color:var(--text-muted);"><?=$total_members?> total members</span>
        </div>
        <table>
          <thead><tr><th>#</th><th>Full Name</th><th>Phone</th><th>Email</th><th>Type</th><th>Join Date</th><th>Action</th></tr></thead>
          <tbody>
          <?php $members=$conn->query("SELECT * FROM members $search_sql ORDER BY full_name ASC");$i=1;
            while($row=$members->fetch_assoc()):?>
          <tr>
            <td style="color:var(--text-muted);font-size:.8rem;"><?=$i++?></td>
            <td><strong><?=htmlspecialchars($row['full_name'])?></strong><?php if($row['other_roles']):?><br><small style="color:var(--text-muted)"><?=htmlspecialchars($row['other_roles'])?></small><?php endif;?></td>
            <td><?=htmlspecialchars($row['phone']?:'—')?></td>
            <td><?=htmlspecialchars($row['email']?:'—')?></td>
            <td><span class="badge badge-blue"><?=htmlspecialchars($row['membership_type']?:'Member')?></span></td>
            <td><?=$row['join_date']?date('M d, Y',strtotime($row['join_date'])):'—'?></td>
            <td>
              <div class="action-group">
                <a href="?page=edit_member&id=<?=$row['id']?>" class="btn-edit">✏️ Edit</a>
                <form class="del-form" method="POST" onsubmit="return confirm('Delete <?=htmlspecialchars(addslashes($row['full_name']))?>')">
                  <input type="hidden" name="delete_member" value="<?=$row['id']?>">
                  <button type="submit" class="btn-del">🗑 Delete</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endwhile;if($members->num_rows===0):?>
          <tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-muted);">No members found.</td></tr>
          <?php endif;?>
          </tbody>
        </table>
      </div>

    <?php /* ═══ ADD MEMBER ═══ */ elseif($page==='add_member'): ?>
      <div class="page-header"><h2>Add New Member</h2><a href="?page=members" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <div class="form-section">Personal Information</div>
          <div class="form-grid">
            <div class="form-group full"><label>Full Name *</label><input type="text" name="full_name" required placeholder="e.g. John Mensah"></div>
            <div class="form-group"><label>Phone Number</label><input type="tel" name="phone" placeholder="+233 XX XXX XXXX"></div>
            <div class="form-group"><label>Email Address</label><input type="email" name="email" placeholder="email@example.com"></div>
            <div class="form-group"><label>Birth Month & Year</label><input type="month" name="birth_date"></div>
            <div class="form-group"><label>Join Date</label><input type="date" name="join_date" value="<?=date('Y-m-d')?>"></div>
            <div class="form-group full"><label>Home Address</label><input type="text" name="address" placeholder="City, Region"></div>
            <div class="form-group full"><label>Hometown</label><input type="text" name="hometown" placeholder="Town, Region"></div>
          </div>
          <div class="form-section">Church Details</div>
          <div class="form-grid">
            <div class="form-group"><label>Membership Type</label>
              <select name="membership_type"><option value="">— Select —</option>
                <?php foreach(['Pastor','Elder','Deacon','Member','Youth','Children'] as $mt):?><option><?=$mt?></option><?php endforeach;?>
              </select>
            </div>
            <div class="form-group"><label>Marital Status</label>
              <select name="marital_status"><option value="">— Select —</option>
                <?php foreach(['Single','Married','Widowed','Divorced'] as $ms):?><option><?=$ms?></option><?php endforeach;?>
              </select>
            </div>
            <div class="form-group full"><label>Other Roles</label><input type="text" name="other_roles" placeholder="e.g. Usher, MC, Choir"></div>
          </div><br>
          <button type="submit" name="add_member" class="btn btn-red">Save Member</button>
          <a href="?page=members" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ EDIT MEMBER ═══ */ elseif($page==='edit_member'&&$edit_member): ?>
      <div class="page-header"><h2>Edit Member</h2><a href="?page=members" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <input type="hidden" name="member_id" value="<?=$edit_member['id']?>">
          <div class="form-section">Personal Information</div>
          <div class="form-grid">
            <div class="form-group full"><label>Full Name *</label><input type="text" name="full_name" required value="<?=htmlspecialchars($edit_member['full_name'])?>"></div>
            <div class="form-group"><label>Phone Number</label><input type="tel" name="phone" value="<?=htmlspecialchars($edit_member['phone'])?>"></div>
            <div class="form-group"><label>Email Address</label><input type="email" name="email" value="<?=htmlspecialchars($edit_member['email'])?>"></div>
            <div class="form-group"><label>Birth Month & Year</label><input type="month" name="birth_date" value="<?= $edit_member['birth_date'] ? date('Y-m', strtotime($edit_member['birth_date'])) : '' ?>"></div>
            <div class="form-group"><label>Join Date</label><input type="date" name="join_date" value="<?=htmlspecialchars($edit_member['join_date'])?>"></div>
            <div class="form-group full"><label>Home Address</label><input type="text" name="address" value="<?=htmlspecialchars($edit_member['address'])?>"></div>
            <div class="form-group full"><label>Hometown</label><input type="text" name="hometown" value="<?=htmlspecialchars($edit_member['hometown'])?>"></div>
          </div>
          <div class="form-section">Church Details</div>
          <div class="form-grid">
            <div class="form-group"><label>Membership Type</label>
              <select name="membership_type"><option value="">— Select —</option>
                <?php foreach(['Pastor','Elder','Deacon','Member','Youth','Children'] as $mt):?>
                <option <?=$edit_member['membership_type']===$mt?'selected':''?>><?=$mt?></option><?php endforeach;?>
              </select>
            </div>
            <div class="form-group"><label>Marital Status</label>
              <select name="marital_status"><option value="">— Select —</option>
                <?php foreach(['Single','Married','Widowed','Divorced'] as $ms):?>
                <option <?=$edit_member['marital_status']===$ms?'selected':''?>><?=$ms?></option><?php endforeach;?>
              </select>
            </div>
            <div class="form-group full"><label>Other Roles</label><input type="text" name="other_roles" value="<?=htmlspecialchars($edit_member['other_roles'])?>" placeholder="e.g. Usher, MC, Choir"></div>
          </div><br>
          <button type="submit" name="edit_member" class="btn btn-red">Update Member</button>
          <a href="?page=members" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ ATTENDANCE ═══ */ elseif($page==='attendance'): ?>
      <div class="page-header"><h2>Attendance Records</h2><a href="?page=add_attendance" class="btn btn-red">+ Record Attendance</a></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Member Name</th><th>Service Date</th><th>Service Type</th></tr></thead>
          <tbody>
          <?php $att=$conn->query("SELECT a.*,m.full_name FROM attendance a LEFT JOIN members m ON a.member_id=m.id ORDER BY a.service_date DESC LIMIT 100");$i=1;
            while($row=$att->fetch_assoc()):?>
          <tr>
            <td style="color:var(--text-muted);font-size:.8rem;"><?=$i++?></td>
            <td><strong><?=htmlspecialchars($row['full_name']??'Unknown')?></strong></td>
            <td><?=date('D, M d, Y',strtotime($row['service_date']))?></td>
            <td><span class="badge badge-blue"><?=htmlspecialchars($row['service_type'])?></span></td>
          </tr>
          <?php endwhile;if($att->num_rows===0):?>
          <tr><td colspan="4" style="text-align:center;padding:30px;color:var(--text-muted);">No attendance records yet.</td></tr>
          <?php endif;?>
          </tbody>
        </table>
      </div>

    <?php elseif($page==='add_attendance'): ?>
      <div class="page-header"><h2>Record Attendance</h2><a href="?page=attendance" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <div class="form-grid">
            <div class="form-group full"><label>Select Member *</label>
              <select name="member_id" required><option value="">— Choose Member —</option>
                <?php $ml=$conn->query("SELECT id,full_name FROM members ORDER BY full_name");while($m=$ml->fetch_assoc()):?>
                <option value="<?=$m['id']?>"><?=htmlspecialchars($m['full_name'])?></option>
                <?php endwhile;?>
              </select>
            </div>
            <div class="form-group"><label>Service Date *</label><input type="date" name="service_date" value="<?=date('Y-m-d')?>" required></div>
            <div class="form-group"><label>Service Type</label>
              <select name="service_type">
                <option>Sunday Service</option><option>Wednesday Bible Study</option>
                <option>Friday Prayer</option><option>Youth Service</option><option>Special Service</option>
              </select>
            </div>
          </div><br>
          <button type="submit" name="add_attendance" class="btn btn-red">Record Attendance</button>
          <a href="?page=attendance" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ EVENTS LIST ═══ */ elseif($page==='events'): ?>
      <div class="page-header"><h2>Church Events</h2><a href="?page=add_event" class="btn btn-red">+ Add Event</a></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Event Name</th><th>Date</th><th>Time</th><th>Location</th><th>Action</th></tr></thead>
          <tbody>
          <?php $evs=$conn->query("SELECT * FROM events ORDER BY event_date ASC");$i=1;
            while($row=$evs->fetch_assoc()):$isPast=strtotime($row['event_date'])<strtotime('today');?>
          <tr>
            <td style="color:var(--text-muted);font-size:.8rem;"><?=$i++?></td>
            <td><strong><?=htmlspecialchars($row['event_name'])?></strong><?php if($row['description']):?><br><small style="color:var(--text-muted)"><?=htmlspecialchars(substr($row['description'],0,60))?>...</small><?php endif;?></td>
            <td><?=date('M d, Y',strtotime($row['event_date']))?><br><?php if($isPast):?><span class="badge badge-gray">Past</span><?php else:?><span class="badge badge-green">Upcoming</span><?php endif;?></td>
            <td><?=$row['event_time']?date('g:i A',strtotime($row['event_time'])):'—'?></td>
            <td><?=htmlspecialchars($row['location']?:'—')?></td>
            <td>
              <div class="action-group">
                <a href="?page=edit_event&id=<?=$row['id']?>" class="btn-edit">✏️ Edit</a>
                <form class="del-form" method="POST" onsubmit="return confirm('Delete this event?')">
                  <input type="hidden" name="delete_event" value="<?=$row['id']?>">
                  <button type="submit" class="btn-del">🗑 Delete</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endwhile;if($evs->num_rows===0):?>
          <tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-muted);">No events added yet.</td></tr>
          <?php endif;?>
          </tbody>
        </table>
      </div>

    <?php elseif($page==='add_event'): ?>
      <div class="page-header"><h2>Add New Event</h2><a href="?page=events" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <div class="form-grid">
            <div class="form-group full"><label>Event Name *</label><input type="text" name="event_name" required placeholder="e.g. Easter Sunday Service"></div>
            <div class="form-group"><label>Date *</label><input type="date" name="event_date" value="<?=date('Y-m-d')?>" required></div>
            <div class="form-group"><label>Time</label><input type="time" name="event_time"></div>
            <div class="form-group full"><label>Location</label><input type="text" name="location" placeholder="e.g. Main Sanctuary, Dome"></div>
            <div class="form-group full"><label>Description</label><textarea name="description" placeholder="Details about the event..."></textarea></div>
          </div><br>
          <button type="submit" name="add_event" class="btn btn-red">Save Event</button>
          <a href="?page=events" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ EDIT EVENT ═══ */ elseif($page==='edit_event'&&$edit_event): ?>
      <div class="page-header"><h2>Edit Event</h2><a href="?page=events" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <input type="hidden" name="event_id" value="<?=$edit_event['id']?>">
          <div class="form-grid">
            <div class="form-group full"><label>Event Name *</label><input type="text" name="event_name" required value="<?=htmlspecialchars($edit_event['event_name'])?>"></div>
            <div class="form-group"><label>Date *</label><input type="date" name="event_date" required value="<?=htmlspecialchars($edit_event['event_date'])?>"></div>
            <div class="form-group"><label>Time</label><input type="time" name="event_time" value="<?=htmlspecialchars($edit_event['event_time'])?>"></div>
            <div class="form-group full"><label>Location</label><input type="text" name="location" value="<?=htmlspecialchars($edit_event['location'])?>"></div>
            <div class="form-group full"><label>Description</label><textarea name="description"><?=htmlspecialchars($edit_event['description'])?></textarea></div>
          </div><br>
          <button type="submit" name="edit_event" class="btn btn-red">Update Event</button>
          <a href="?page=events" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ SERMONS LIST ═══ */ elseif($page==='sermons'): ?>
      <div class="page-header"><h2>Sermon Records</h2><a href="?page=add_sermon" class="btn btn-red">+ Add Sermon</a></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Sermon Title</th><th>Preacher</th><th>Date</th><th>Scripture</th><th>Notes</th><th>Action</th></tr></thead>
          <tbody>
          <?php $serm=$conn->query("SELECT * FROM sermons ORDER BY sermon_date DESC");$i=1;
            while($row=$serm->fetch_assoc()):?>
          <tr>
            <td style="color:var(--text-muted);font-size:.8rem;"><?=$i++?></td>
            <td><strong><?=htmlspecialchars($row['title'])?></strong></td>
            <td><?=htmlspecialchars($row['preacher']?:'—')?></td>
            <td><?=date('M d, Y',strtotime($row['sermon_date']))?></td>
            <td><span class="badge badge-red"><?=htmlspecialchars($row['scripture_reference']?:'—')?></span></td>
            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?=htmlspecialchars($row['notes']?:'—')?></td>
            <td>
              <div class="action-group">
                <a href="?page=edit_sermon&id=<?=$row['id']?>" class="btn-edit">✏️ Edit</a>
                <form class="del-form" method="POST" onsubmit="return confirm('Delete this sermon?')">
                  <input type="hidden" name="delete_sermon" value="<?=$row['id']?>">
                  <button type="submit" class="btn-del">🗑 Delete</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endwhile;if($serm->num_rows===0):?>
          <tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-muted);">No sermons recorded yet.</td></tr>
          <?php endif;?>
          </tbody>
        </table>
      </div>

    <?php elseif($page==='add_sermon'): ?>
      <div class="page-header"><h2>Add Sermon</h2><a href="?page=sermons" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <div class="form-grid">
            <div class="form-group full"><label>Sermon Title *</label><input type="text" name="title" required placeholder="e.g. The Power of Redemption"></div>
            <div class="form-group"><label>Preacher</label><input type="text" name="preacher" placeholder="Pastor's name"></div>
            <div class="form-group"><label>Date *</label><input type="date" name="sermon_date" value="<?=date('Y-m-d')?>" required></div>
            <div class="form-group full"><label>Scripture Reference</label><input type="text" name="scripture_reference" placeholder="e.g. Romans 8:1"></div>
            <div class="form-group full"><label>Notes</label><textarea name="notes" placeholder="Sermon notes or summary..."></textarea></div>
          </div><br>
          <button type="submit" name="add_sermon" class="btn btn-red">Save Sermon</button>
          <a href="?page=sermons" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ EDIT SERMON ═══ */ elseif($page==='edit_sermon'&&$edit_sermon): ?>
      <div class="page-header"><h2>Edit Sermon</h2><a href="?page=sermons" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <input type="hidden" name="sermon_id" value="<?=$edit_sermon['id']?>">
          <div class="form-grid">
            <div class="form-group full"><label>Sermon Title *</label><input type="text" name="title" required value="<?=htmlspecialchars($edit_sermon['title'])?>"></div>
            <div class="form-group"><label>Preacher</label><input type="text" name="preacher" value="<?=htmlspecialchars($edit_sermon['preacher'])?>"></div>
            <div class="form-group"><label>Date *</label><input type="date" name="sermon_date" required value="<?=htmlspecialchars($edit_sermon['sermon_date'])?>"></div>
            <div class="form-group full"><label>Scripture Reference</label><input type="text" name="scripture_reference" value="<?=htmlspecialchars($edit_sermon['scripture_reference'])?>"></div>
            <div class="form-group full"><label>Notes</label><textarea name="notes"><?=htmlspecialchars($edit_sermon['notes'])?></textarea></div>
          </div><br>
          <button type="submit" name="edit_sermon" class="btn btn-red">Update Sermon</button>
          <a href="?page=sermons" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ MINISTRIES LIST ═══ */ elseif($page==='ministries'): ?>
      <div class="page-header"><h2>Ministries</h2><a href="?page=add_ministry" class="btn btn-red">+ Add Ministry</a></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Ministry Name</th><th>Leader</th><th>Description</th><th>Action</th></tr></thead>
          <tbody>
          <?php $min=$conn->query("SELECT * FROM ministries ORDER BY ministry_name");$i=1;
            while($row=$min->fetch_assoc()):?>
          <tr>
            <td style="color:var(--text-muted);font-size:.8rem;"><?=$i++?></td>
            <td><strong><?=htmlspecialchars($row['ministry_name'])?></strong></td>
            <td><?=htmlspecialchars($row['leader']?:'—')?></td>
            <td><?=htmlspecialchars($row['description']?:'—')?></td>
            <td>
              <div class="action-group">
                <a href="?page=edit_ministry&id=<?=$row['id']?>" class="btn-edit">✏️ Edit</a>
                <form class="del-form" method="POST" onsubmit="return confirm('Delete this ministry?')">
                  <input type="hidden" name="delete_ministry" value="<?=$row['id']?>">
                  <button type="submit" class="btn-del">🗑 Delete</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endwhile;if($min->num_rows===0):?>
          <tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-muted);">No ministries yet. Click "+ Add Ministry" to get started.</td></tr>
          <?php endif;?>
          </tbody>
        </table>
      </div>

    <?php /* ═══ ADD MINISTRY ═══ */ elseif($page==='add_ministry'): ?>
      <div class="page-header"><h2>Add Ministry</h2><a href="?page=ministries" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <div class="form-grid">
            <div class="form-group full"><label>Ministry Name *</label><input type="text" name="ministry_name" required placeholder="e.g. Choir, Ushers, Youth Ministry"></div>
            <div class="form-group full"><label>Ministry Leader</label><input type="text" name="leader" placeholder="Name of leader or head"></div>
            <div class="form-group full"><label>Description</label><textarea name="description" placeholder="What this ministry does..."></textarea></div>
          </div><br>
          <button type="submit" name="add_ministry" class="btn btn-red">Save Ministry</button>
          <a href="?page=ministries" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php /* ═══ EDIT MINISTRY ═══ */ elseif($page==='edit_ministry'&&$edit_ministry): ?>
      <div class="page-header"><h2>Edit Ministry</h2><a href="?page=ministries" class="btn btn-outline">← Back</a></div>
      <div class="form-card">
        <form method="POST">
          <input type="hidden" name="ministry_id" value="<?=$edit_ministry['id']?>">
          <div class="form-grid">
            <div class="form-group full"><label>Ministry Name *</label><input type="text" name="ministry_name" required value="<?=htmlspecialchars($edit_ministry['ministry_name'])?>"></div>
            <div class="form-group full"><label>Ministry Leader</label><input type="text" name="leader" value="<?=htmlspecialchars($edit_ministry['leader'])?>"></div>
            <div class="form-group full"><label>Description</label><textarea name="description"><?=htmlspecialchars($edit_ministry['description'])?></textarea></div>
          </div><br>
          <button type="submit" name="edit_ministry" class="btn btn-red">Update Ministry</button>
          <a href="?page=ministries" class="btn btn-outline">Cancel</a>
        </form>
      </div>

    <?php endif;?>
  </div>
</div>
</body>
</html>
