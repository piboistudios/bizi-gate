'use strict';
var mongoose = require('mongoose')
    , ObjectId = mongoose.Schema.Types.ObjectId;

var schema = new mongoose.Schema({
    dest: {
        required: true,
        type: {
            host: { required: true, type: String },
            port: { required: true, type: Number },
            protocol: { required: true, type: String, default: "TCP" },
            tlsTermination: { required: true, type: Boolean, default: true }
        }
    },
    src: {
        required: true,
        type: {
            host: {
                required: true,
                type: ObjectId,
                ref: "gate.VirtualHost"
            },
            port: Number
        }

    },
    client: { ref: "Client", type: ObjectId }
});

module.exports = mongoose.model('gate.Registration', schema);
