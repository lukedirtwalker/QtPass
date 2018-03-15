#include "../../../src/passworddialog.h"
#include <QCoreApplication>
#include <QtTest>

/**
 * @brief The tst_ui class is our first unit test
 */
class tst_ui : public QObject {
  Q_OBJECT

private Q_SLOTS:
  void contentRemainsSame();
};

/**
 * @brief tst_ui::contentRemainsSame test that content set with PasswordDialog::setPassword
 * is repeated when calling PasswordDialog::getPassword.
 */
void tst_ui::contentRemainsSame() {
  QScopedPointer<PasswordDialog> d(new PasswordDialog(passwordConfiguration{}, NULL));
  d->setTemplate("", false);
  QString input = "pw\n";
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);

  d.reset(new PasswordDialog(passwordConfiguration{}, NULL));
  input = "pw\nname: value\n";
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);

  d.reset(new PasswordDialog(passwordConfiguration{}, NULL));
  d->setTemplate("name", false);
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);

  d.reset(new PasswordDialog(passwordConfiguration{}, NULL));
  d->setTemplate("name", true);
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);

  d.reset(new PasswordDialog(passwordConfiguration{}, NULL));
  d->setTemplate("", false);
  d->templateAll(true);
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);

  d.reset(new PasswordDialog(passwordConfiguration{}, NULL));
  d->setTemplate("", true);
  d->templateAll(true);
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);

  d.reset(new PasswordDialog(passwordConfiguration{}, NULL));
  d->setTemplate("name", true);
  d->templateAll(true);
  d->setPass(input);
  QCOMPARE(d->getPassword(), input);
}

QTEST_MAIN(tst_ui)
#include "tst_ui.moc"