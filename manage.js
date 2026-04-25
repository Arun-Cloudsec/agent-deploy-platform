#!/usr/bin/env node
/**
 * RFP Agent — Admin CLI
 * Usage:
 *   node manage.js create-user <email> <password> [orgName]
 *   node manage.js list-users
 *   node manage.js delete-user <email>
 *   node manage.js reset-password <email> <newpassword>
 */

const { db } = require('./server.js');
const bcrypt  = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const [,, cmd, ...args] = process.argv;

async function run() {
  switch (cmd) {

    case 'create-user': {
      const [email, password, orgName] = args;
      if (!email || !password) {
        console.error('Usage: node manage.js create-user <email> <password> [orgName]');
        process.exit(1);
      }
      if (password.length < 8) {
        console.error('❌ Password must be at least 8 characters');
        process.exit(1);
      }
      const existing = db.getUser(email.toLowerCase());
      if (existing) {
        console.error('❌ Email already registered:', email.toLowerCase());
        process.exit(1);
      }
      const id    = uuidv4();
      const token = uuidv4() + uuidv4();
      db.createUser({
        id,
        email:         email.toLowerCase(),
        password_hash: await bcrypt.hash(password, 10),
        token,
        org_name:      orgName || '',
        org_industry:  'Technology / IT',
        org_years:     '',
        org_bio:       '',
        api_key:       '',
        created_at:    new Date().toISOString()
      });
      console.log('\n✅ User created successfully!');
      console.log('   Email   :', email.toLowerCase());
      console.log('   Org     :', orgName || '(not set — update in Settings)');
      console.log('\n   You can now log in at your RFP Agent URL.\n');
      break;
    }

    case 'list-users': {
      const d = require('./data/db.json');
      const users = d.users || [];
      if (!users.length) {
        console.log('\n  No users registered yet.\n');
        break;
      }
      console.log('\n  Registered users (' + users.length + '):\n');
      users.forEach((u, i) => {
        console.log(`  ${i+1}. ${u.email}  |  org: ${u.org_name||'—'}  |  created: ${u.created_at.split('T')[0]}`);
      });
      console.log('');
      break;
    }

    case 'delete-user': {
      const [email] = args;
      if (!email) {
        console.error('Usage: node manage.js delete-user <email>');
        process.exit(1);
      }
      const user = db.getUser(email.toLowerCase());
      if (!user) {
        console.error('❌ User not found:', email);
        process.exit(1);
      }
      const d = require('./data/db.json');
      const fs = require('fs');
      const path = require('path');
      d.users    = d.users.filter(u => u.email !== email.toLowerCase());
      d.library  = (d.library  || []).filter(l => l.user_id !== user.id);
      d.recent   = (d.recent   || []).filter(r => r.user_id !== user.id);
      d.estimations = (d.estimations || []).filter(e => e.user_id !== user.id);
      fs.writeFileSync(path.join(__dirname, 'data', 'db.json'), JSON.stringify(d, null, 2));
      console.log('\n✅ User deleted:', email.toLowerCase(), '\n');
      break;
    }

    case 'reset-password': {
      const [email, newPassword] = args;
      if (!email || !newPassword) {
        console.error('Usage: node manage.js reset-password <email> <newpassword>');
        process.exit(1);
      }
      if (newPassword.length < 8) {
        console.error('❌ Password must be at least 8 characters');
        process.exit(1);
      }
      const user = db.getUser(email.toLowerCase());
      if (!user) {
        console.error('❌ User not found:', email);
        process.exit(1);
      }
      db.updateUser(user.id, {
        password_hash: await bcrypt.hash(newPassword, 10),
        token: uuidv4() + uuidv4() // invalidate existing sessions
      });
      console.log('\n✅ Password reset for:', email.toLowerCase());
      console.log('   All existing sessions have been invalidated.\n');
      break;
    }

    default: {
      console.log('\n  RFP Agent — Admin CLI\n');
      console.log('  Commands:');
      console.log('    node manage.js create-user <email> <password> [orgName]');
      console.log('    node manage.js list-users');
      console.log('    node manage.js delete-user <email>');
      console.log('    node manage.js reset-password <email> <newpassword>\n');
    }
  }
}

run().catch(e => {
  console.error('❌ Error:', e.message);
  process.exit(1);
});
