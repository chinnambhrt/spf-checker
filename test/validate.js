const { expect } = require('chai');
const { validateSPF } = require('../lib/index')


describe('Should validate SPF records', () => {

    it('Should validate redirect SPF record', (done) => {

        validateSPF('35.190.247.16', 'gmail.com')

            .then(resp => {

                const result = resp.result;
                
                expect(result).to.be.equal('pass');

                done();

            }).catch(err => {
                done(err);
            });

    });

    it('Should validate include SPF record', (done) => {

        validateSPF('209.61.151.16', 'mailgun.org')

            .then(resp => {

                const result = resp.result;
                expect(result).to.be.equal('pass');
                done();

            }).catch(err => {
                done(err);
            });

    });

    // validate ip record
    it('Should validate ip4 SPF record', (done) => {

        validateSPF('166.78.69.169', 'github.com')
            .then(resp => {
                const result = resp.result;
                expect(result).to.be.equal('pass');
                done();

            }).catch(err => {
                done(err);
            });

    });




});