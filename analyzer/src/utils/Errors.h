#ifndef _CONDITION_SOLVER_ERRORS_H
#define _CONDITION_SOLVER_ERRORS_H

#include <exception>
#include <string>
#include <sys/cdefs.h>
#include "utils.h"
#include "format.hh"

using namespace std;

class ConditionSolverException : public exception{};
class NotImplementConstant : public ConditionSolverException{};
class NotImplementExpr : public ConditionSolverException{};

class GeneralException : public exception {
public:
    string errmsg;
    
    GeneralException() {
        this->errmsg = "Empty exception message.";
    }
    GeneralException(string errmsg, bool log=true, string log_name="Exception") {
        this->errmsg = errmsg;
        if (log) { this->log(log_name); }
        
    }
    template <typename... Args>
    GeneralException(string msgFmt, Args... args) {
        this->errmsg = util::Format(msgFmt, args...);
        this->log();
    }

    virtual const char * what() const throw() {
        return this->errmsg.c_str();
    }

    virtual void log(string log_name="Exception") {
        auto logger = logging::get(log_name);
        if (logger) { logger->warn(this->errmsg); } // should set flush_on already
    }
};

#endif